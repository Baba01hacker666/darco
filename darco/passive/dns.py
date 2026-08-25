from __future__ import annotations

import socket

import httpx

from ..models import DnsRecord, Finding

# DNS Record Type Mapping
DNS_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
}

DOH_ENDPOINTS = [
    ("https://cloudflare-dns.com/dns-query", {"accept": "application/dns-json"}),
    ("https://dns.google/resolve", {}),
]


async def query_doh_record(
    client: httpx.AsyncClient, domain: str, rtype: str
) -> list[DnsRecord]:
    """Query DNS over HTTPS for a specific record type."""
    records: list[DnsRecord] = []
    type_id = DNS_TYPES.get(rtype.upper(), 1)

    for doh_url, headers in DOH_ENDPOINTS:
        try:
            resp = await client.get(
                doh_url,
                params={"name": domain, "type": type_id},
                headers=headers,
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                for ans in answers:
                    val = str(ans.get("data", "")).strip(' "')
                    name = str(ans.get("name", "")).rstrip(".")
                    ttl = ans.get("TTL")
                    ans_type = ans.get("type")
                    # Check if matches requested type or is CNAME
                    rec_type = rtype
                    for k, v in DNS_TYPES.items():
                        if v == ans_type:
                            rec_type = k
                            break
                    records.append(
                        DnsRecord(
                            record_type=rec_type,
                            name=name,
                            value=val,
                            ttl=ttl,
                        )
                    )
                if records or data.get("Status") == 0:
                    break
        except (httpx.HTTPError, ValueError, KeyError):
            continue

    return records


async def enumerate_dns(
    domain: str, client: httpx.AsyncClient | None = None
) -> tuple[list[DnsRecord], list[Finding]]:
    """Enumerate DNS records for a domain and analyze email/security posture."""
    records: list[DnsRecord] = []
    findings: list[Finding] = []
    own_client = False

    if client is None:
        client = httpx.AsyncClient(timeout=6.0, trust_env=False)
        own_client = True

    try:
        # 1. Query standard record types
        for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"]:
            recs = await query_doh_record(client, domain, rtype)
            records.extend(recs)

        # 2. Query DMARC record specifically
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_recs = await query_doh_record(client, dmarc_domain, "TXT")
        records.extend(dmarc_recs)

        # Fallback local socket resolution if DoH failed for A records
        if not any(r.record_type == "A" for r in records):
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                for ip in ips:
                    records.append(
                        DnsRecord(record_type="A", name=domain, value=ip)
                    )
            except socket.gaierror:
                pass

        # 3. Analyze SPF / DMARC / CAA Posture
        txt_values = [r.value for r in records if r.record_type == "TXT" and r.name.lower() == domain.lower()]
        spf_records = [v for v in txt_values if v.lower().startswith("v=spf1")]

        if not spf_records:
            findings.append(
                Finding(
                    id="find-dns-spf-missing",
                    type="missing_spf",
                    severity="medium",
                    location=f"DNS TXT {domain}",
                    evidence="No SPF (v=spf1) record found in DNS TXT",
                    suggestion="Add a valid SPF TXT record (e.g. 'v=spf1 -all' or include authorized mail servers) to prevent email spoofing.",
                )
            )
        else:
            spf = spf_records[0]
            if "+all" in spf:
                findings.append(
                    Finding(
                        id="find-dns-spf-plus-all",
                        type="spf_misconfiguration",
                        severity="high",
                        location=f"DNS TXT {domain}",
                        evidence=f"SPF record contains '+all': {spf}",
                        suggestion="Change '+all' to '~all' (SoftFail) or '-all' (HardFail) to prevent unauthorized domains from sending mail.",
                    )
                )
            elif "?all" in spf:
                findings.append(
                    Finding(
                        id="find-dns-spf-neutral",
                        type="spf_weak_policy",
                        severity="low",
                        location=f"DNS TXT {domain}",
                        evidence=f"SPF record contains neutral '?all': {spf}",
                        suggestion="Upgrade neutral '?all' to '~all' or '-all' for stronger email authentication.",
                    )
                )

        dmarc_values = [
            r.value for r in records if r.record_type == "TXT" and "_dmarc" in r.name.lower()
        ]
        if not dmarc_values:
            findings.append(
                Finding(
                    id="find-dns-dmarc-missing",
                    type="missing_dmarc",
                    severity="medium",
                    location=f"DNS TXT _dmarc.{domain}",
                    evidence="No DMARC (v=DMARC1) record found in DNS TXT",
                    suggestion="Add a DMARC TXT record at _dmarc.<domain> with policy 'p=quarantine' or 'p=reject' to protect domain reputation.",
                )
            )
        else:
            dmarc = dmarc_values[0]
            if "p=none" in dmarc.lower():
                findings.append(
                    Finding(
                        id="find-dns-dmarc-none",
                        type="dmarc_none_policy",
                        severity="low",
                        location=f"DNS TXT _dmarc.{domain}",
                        evidence=f"DMARC policy is set to 'p=none' (monitoring only): {dmarc}",
                        suggestion="Enforce email protection by progressing DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
                    )
                )

        # Check CAA record
        has_caa = any(r.record_type == "CAA" for r in records)
        if not has_caa:
            findings.append(
                Finding(
                    id="find-dns-caa-missing",
                    type="missing_caa",
                    severity="low",
                    location=f"DNS CAA {domain}",
                    evidence="No CAA record found in DNS",
                    suggestion="Add CAA (Certificate Authority Authorization) records to restrict which CAs are permitted to issue certificates for this domain.",
                )
            )

    finally:
        if own_client:
            await client.aclose()

    # Deduplicate records
    unique_records: list[DnsRecord] = []
    seen = set()
    for r in records:
        key = (r.record_type, r.name.lower(), r.value)
        if key not in seen:
            seen.add(key)
            unique_records.append(r)

    return sorted(unique_records, key=lambda x: (x.record_type, x.name)), findings
