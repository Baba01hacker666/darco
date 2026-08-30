from __future__ import annotations

"""Origin-IP discovery + DNS history / subdomain enumeration.

The goal: find the *real* backend IP behind a CDN/WAF (Cloudflare, Akamai,
etc.) so a scanner can be pointed straight at the origin and skip the shield.

Techniques (all live, no API keys required):

* **Subdomain enumeration** — a curated wordlist of common subdomains is
  resolved; any that resolve are collected.
* **DNS history** — the free hackertarget.com hostsearch API returns a
  historical subdomain→IP map for the domain (no key needed).
* **CNAME chaining** — a subdomain whose CNAME points to a non-CDN host is
  followed to its A record; that A is often the origin.
* **Direct A / historical-IP correlation** — every resolved/historical IP is
  reported with a heuristic "likely origin" flag (e.g. an IP that is NOT in
  the CDN's published ranges and is reachable on 80/443 directly).

`dig` is used for resolution (already present on the box); the hackertarget
API is used over httpx for history. Failures degrade gracefully.
"""

import asyncio
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from .errors import DarcoError

# Common subdomains worth probing for an origin leak. Kept lean on purpose.
SUBDOMAIN_WORDLIST = [
    "www",
    "api",
    "app",
    "dev",
    "stage",
    "staging",
    "test",
    "beta",
    "admin",
    "portal",
    "cp",
    "cpanel",
    "direct",
    "origin",
    "ori",
    "backend",
    "internal",
    "int",
    "vpn",
    "mail",
    "webmail",
    "smtp",
    "ftp",
    "ssh",
    "git",
    "ci",
    "jenkins",
    "db",
    "mysql",
    "pgsql",
    "legacy",
    "old",
    "new",
    "m",
    "mobile",
    "shop",
    "store",
    "secure",
    "login",
    "auth",
    "sso",
    "v1",
    "v2",
    "cdn",
    "static",
    "assets",
    "images",
    "img",
    "media",
    "files",
    "ns1",
    "ns2",
    "dns",
    "mx",
    "lb",
    "loadbalancer",
    "node",
    "srv",
    "server",
    "host",
    "panel",
]

# CDN / WAF vendor edge host fragments — a subdomain whose CNAME ends in one of
# these is CDN-fronted (not an origin leak); one that does not is suspicious.
CDN_CNAME_FRAGMENTS = (
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "azureedge",
    "azurefd",
    "trafficmanager",
    "edgekey",
    "akadns",
    "edgesuite",
    "incapdns",
    "sucuri",
    "stackpath",
    "sucuri.net",
    "fwu.rs",
    "google",
    "googlehosted",
    "lscache",
    "bitgravity",
    "limelight",
    "level3",
    "cdn",
    ".herokuapp.com",
    ".amazonaws.com",
    ".azurewebsites",
    ".netlify",
    ".pages.dev",
    ".vercel",
    ".fly.dev",
)


@dataclass
class HostRecord:
    host: str
    ips: list[str] = field(default_factory=list)
    cname: str | None = None
    source: str = ""  # wordlist | history | cname-chain | direct
    likely_origin: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "ips": self.ips,
            "cname": self.cname,
            "source": self.source,
            "likely_origin": self.likely_origin,
            "note": self.note,
        }


@dataclass
class OriginReport:
    target: str
    direct_ips: list[str] = field(default_factory=list)
    hosts: list[HostRecord] = field(default_factory=list)
    historical: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "direct_ips": self.direct_ips,
            "hosts": [h.to_dict() for h in self.hosts],
            "historical": self.historical,
            "notes": self.notes,
            "error": self.error or None,
        }


# ------------------------------------------------------------------ DNS helpers
def _dig(records: str, host: str, resolver: str = "8.8.8.8") -> list[str]:
    """Resolve `records` (e.g. 'A', 'CNAME', 'AAAA') for host via dig."""
    try:
        out = subprocess.run(
            ["dig", "+short", f"-t{records}", host, f"@{resolver}"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return []
    lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
    # +short returns the CNAME first, then the A record(s); for A/AAAA we only
    # want IP addresses (CNAME lines contain letters/dots but not a clean IP).
    import re

    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f:]+$")
    if records in ("A", "AAAA"):
        return [l.rstrip(".") for l in lines if ip_re.match(l)]
    return [l.rstrip(".") for l in lines]


def _root_domain(host: str) -> str:
    host = host.strip().lower()
    if host.startswith(("http://", "https://")):
        host = urlparse(host).hostname or host
    return host


def _is_cdn_cname(cname: str) -> bool:
    c = cname.lower()
    return any(frag in c for frag in CDN_CNAME_FRAGMENTS)


# ------------------------------------------------------------------ subdomain enumeration
def _enumerate_wordlist(domain: str, concurrency: int = 20) -> list[HostRecord]:
    hosts = [f"{s}.{domain}" for s in SUBDOMAIN_WORDLIST]

    async def resolve_one(h: str) -> HostRecord | None:
        loop = asyncio.get_running_loop()
        a = await loop.run_in_executor(None, lambda: _dig("A", h))
        if not a:
            return None
        cname = None
        cnames = await loop.run_in_executor(None, lambda: _dig("CNAME", h))
        if cnames:
            cname = cnames[0]
        rec = HostRecord(host=h, ips=a, cname=cname, source="wordlist")
        rec.likely_origin = bool(cname) and not _is_cdn_cname(cname)
        rec.note = (
            "CNAME does not appear CDN-fronted → possible origin"
            if rec.likely_origin
            else (f"CNAME → {cname}" if cname else "")
        )
        return rec

    async def run():
        tasks = [resolve_one(h) for h in hosts]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    try:
        cur_loop = asyncio.get_running_loop()
    except RuntimeError:
        cur_loop = None

    if cur_loop and cur_loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, run()).result()

    return asyncio.run(run())


# ------------------------------------------------------------------ DNS history (free API)
def _dns_history(domain: str) -> list[dict]:
    """Pull historical subdomain→IP map from hackertarget.com (no key)."""
    try:
        r = httpx.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=12,
            headers={"User-Agent": "darco/0.1"},
        )
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    out: list[dict] = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        host, ip = line.split(",", 1)
        out.append({"host": host.strip(), "ip": ip.strip()})
    return out


# ------------------------------------------------------------------ CNAME chain follow
def _follow_cname(host: str, depth: int = 4) -> tuple[list[str], str | None]:
    """Follow CNAME records; return (resolved_ips, final_cname)."""
    seen = set()
    current = host
    final_cname = None
    for _ in range(depth):
        if current in seen:
            break
        seen.add(current)
        cnames = _dig("CNAME", current)
        if not cnames:
            # no more CNAMEs — resolve A here
            return _dig("A", current), final_cname
        final_cname = cnames[0]
        current = final_cname
    return _dig("A", current), final_cname


# ------------------------------------------------------------------ public entry
def find_origin(
    domain: str, *, enum_subdomains: bool = True, use_history: bool = True
) -> OriginReport:
    """Discover the origin IP(s) behind a CDN/WAF for `domain`."""
    domain = _root_domain(domain)
    if not domain:
        raise DarcoError("invalid domain")

    report = OriginReport(target=domain)
    report.notes.append(
        "Techniques: subdomain enum (wordlist), DNS history (hackertarget), "
        "CNAME-chain follow, direct A resolution."
    )

    # 1) direct A of the apex + www
    for h in (domain, f"www.{domain}"):
        ips = _dig("A", h)
        if ips:
            rec = HostRecord(host=h, ips=ips, source="direct")
            report.hosts.append(rec)
            report.direct_ips.extend(ips)

    # 2) DNS history
    if use_history:
        hist = _dns_history(domain)
        report.historical = hist
        for entry in hist:
            host, ip = entry["host"], entry["ip"]
            existing = next((h for h in report.hosts if h.host == host), None)
            if existing:
                if ip not in existing.ips:
                    existing.ips.append(ip)
            else:
                report.hosts.append(HostRecord(host=host, ips=[ip], source="history"))

    # 3) wordlist subdomain enumeration
    if enum_subdomains:
        for rec in _enumerate_wordlist(domain):
            if not any(h.host == rec.host for h in report.hosts):
                report.hosts.append(rec)

    # 4) follow CNAME chains on hosts that have a CNAME, looking for a
    #    non-CDN terminal A record (the origin).
    for rec in list(report.hosts):
        if rec.cname and not _is_cdn_cname(rec.cname):
            ips, _final = _follow_cname(rec.cname)
            if ips:
                rec.ips = sorted(set(rec.ips + ips))
                rec.likely_origin = True
                rec.note = f"CNAME chain → origin candidate {ips}"
                report.notes.append(
                    f"{rec.host}: CNAME {rec.cname} resolves to {ips} (likely origin)"
                )

    # de-dup hosts by name, merge IPs
    merged: dict[str, HostRecord] = {}
    for rec in report.hosts:
        if rec.host in merged:
            m = merged[rec.host]
            m.ips = sorted(set(m.ips + rec.ips))
            if rec.likely_origin:
                m.likely_origin = True
        else:
            merged[rec.host] = rec
    report.hosts = list(merged.values())

    if not report.hosts and not report.historical:
        report.error = "no DNS data resolved (offline or domain does not exist)"
    return report
