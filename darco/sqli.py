import re
from difflib import SequenceMatcher

import httpx

from .engine import execute
from .models import (
    NameValue,
    Request,
    Response,
    SessionState,
    SqliFinding,
    SqliScanResult,
)

# Database Error Signatures: (Engine Name, Regex Pattern)
DB_ERRORS: list[tuple[str, re.Pattern]] = [
    # MySQL / MariaDB
    ("MySQL", re.compile(r"You have an error in your SQL syntax", re.IGNORECASE)),
    ("MySQL", re.compile(r"Warning: mysql_", re.IGNORECASE)),
    ("MySQL", re.compile(r"MySQL server version for the right syntax to use", re.IGNORECASE)),
    ("MySQL", re.compile(r"valid MySQL result", re.IGNORECASE)),
    ("MySQL", re.compile(r"com\.mysql\.jdbc\.exceptions", re.IGNORECASE)),
    ("MySQL", re.compile(r"MySqlClient\.", re.IGNORECASE)),
    # PostgreSQL
    ("PostgreSQL", re.compile(r"ERROR:\s*syntax error at or near", re.IGNORECASE)),
    ("PostgreSQL", re.compile(r"PostgreSQL query failed:", re.IGNORECASE)),
    ("PostgreSQL", re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE)),
    ("PostgreSQL", re.compile(r"pg_query\(\): Query failed", re.IGNORECASE)),
    ("PostgreSQL", re.compile(r"PG::SyntaxError", re.IGNORECASE)),
    # Microsoft SQL Server (MSSQL)
    ("MSSQL", re.compile(r"Unclosed quotation mark before the character string", re.IGNORECASE)),
    ("MSSQL", re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE)),
    ("MSSQL", re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.IGNORECASE)),
    ("MSSQL", re.compile(r"Line \d+: Incorrect syntax near", re.IGNORECASE)),
    ("MSSQL", re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE)),
    # Oracle
    ("Oracle", re.compile(r"ORA-00933:\s*SQL command not properly ended", re.IGNORECASE)),
    ("Oracle", re.compile(r"ORA-00936:\s*missing expression", re.IGNORECASE)),
    ("Oracle", re.compile(r"ORA-01756:\s*quoted string not properly terminated", re.IGNORECASE)),
    ("Oracle", re.compile(r"Oracle error", re.IGNORECASE)),
    ("Oracle", re.compile(r"quoted string not properly terminated", re.IGNORECASE)),
    # SQLite
    ("SQLite", re.compile(r"near \".*\": syntax error", re.IGNORECASE)),
    ("SQLite", re.compile(r"SQLite3::SQLException", re.IGNORECASE)),
    ("SQLite", re.compile(r"sqlite3\.OperationalError:", re.IGNORECASE)),
    ("SQLite", re.compile(r"no such table:", re.IGNORECASE)),
    # Microsoft Access / Jet
    ("MS Access", re.compile(r"Syntax error in query expression", re.IGNORECASE)),
    ("MS Access", re.compile(r"Data type mismatch in criteria expression", re.IGNORECASE)),
    ("MS Access", re.compile(r"Microsoft Access Database Engine", re.IGNORECASE)),
]


def _match_db_error(body: str) -> tuple[str, str] | None:
    """Return (db_engine, matched_snippet) if a known DB error pattern is found in body."""
    if not body:
        return None
    for engine, pat in DB_ERRORS:
        m = pat.search(body)
        if m:
            snippet = m.group(0)[:80].replace("\n", " ").strip()
            return engine, snippet
    return None


def _similarity(a: str, b: str) -> float:
    """Compute structural similarity between two response bodies."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    # Sample up to 2000 chars for fast comparison
    return SequenceMatcher(None, a[:2000], b[:2000]).ratio()


def _clone_and_mutate_param(
    base: Request, param_type: str, param_name: str, new_val: str
) -> Request:
    """Clone request and substitute parameter value."""
    req = base.model_copy(deep=True)
    if param_type == "query":
        new_params = []
        for p in req.params:
            if p.name == param_name:
                new_params.append(NameValue(name=p.name, value=new_val))
            else:
                new_params.append(p)
        req.params = new_params
    elif param_type == "form":
        new_form = []
        for p in req.body_form:
            if p.name == param_name:
                new_form.append(NameValue(name=p.name, value=new_val))
            else:
                new_form.append(p)
        req.body_form = new_form
    elif param_type == "json" and isinstance(req.body_json, dict):
        d = dict(req.body_json)
        d[param_name] = new_val
        req.body_json = d
    return req


def _send(req: Request, session: SessionState) -> Response | None:
    """Execute a request and return the darco Response model or None on failure."""
    try:
        res = execute(req, session)
        if isinstance(res, tuple) and len(res) >= 2:
            return res[1]
        elif isinstance(res, Response):
            return res
        return None
    except (httpx.HTTPError, OSError, TimeoutError, ValueError):
        return None


def scan_sqli(
    request: Request,
    session: SessionState | None = None,
    baseline_response: Response | None = None,
    param_filter: str | None = None,
) -> SqliScanResult:
    """Run active SQL injection differential and heuristic checks on a request."""
    if session is None:
        session = SessionState()

    # 1. Fetch baseline response if not provided
    if baseline_response is None:
        baseline_response = _send(request, session)
        if baseline_response is None:
            return SqliScanResult(
                target=request.url,
                tested_params=[],
                vulnerabilities=[
                    SqliFinding(
                        param="target",
                        param_type="target",
                        injection_type="error",
                        confidence="potential",
                        payload="",
                        baseline_status=0,
                        payload_status=0,
                        evidence="Baseline request failed or timed out.",
                        suggestion="Verify target connectivity.",
                    )
                ],
            )

    base_status = baseline_response.status_code
    base_body = baseline_response.body or ""
    base_len = baseline_response.body_len

    # 2. Extract testable parameters
    params_to_test: list[tuple[str, str, str]] = []  # (param_type, param_name, original_val)

    for p in request.params:
        if param_filter is None or p.name == param_filter:
            params_to_test.append(("query", p.name, p.value or ""))

    for p in request.body_form:
        if param_filter is None or p.name == param_filter:
            params_to_test.append(("form", p.name, p.value or ""))

    if isinstance(request.body_json, dict):
        for k, v in request.body_json.items():
            if param_filter is None or k == param_filter:
                params_to_test.append(("json", k, str(v) if v is not None else ""))

    result = SqliScanResult(
        target=request.url,
        tested_params=[p[1] for p in params_to_test],
    )

    for p_type, p_name, orig_val in params_to_test:
        is_numeric = bool(orig_val.isdigit())
        num_val = int(orig_val) if is_numeric else 0

        # --- Test A: Syntax Break Probe (Quote Injection) ---
        break_payload = f"{orig_val}'" if orig_val else "'"
        req_break = _clone_and_mutate_param(request, p_type, p_name, break_payload)
        resp_break = _send(req_break, session)

        if resp_break:
            # Check 1: Explicit Database Error (Confirmed Error-based SQLi)
            db_err = _match_db_error(resp_break.body or "")
            if db_err:
                db_engine, err_snippet = db_err
                result.vulnerabilities.append(
                    SqliFinding(
                        param=p_name,
                        param_type=p_type,
                        injection_type="error_based",
                        db_engine=db_engine,
                        confidence="confirmed",
                        payload=break_payload,
                        baseline_status=base_status,
                        payload_status=resp_break.status_code,
                        evidence=f"Database syntax error leaked ({db_engine}): '{err_snippet}'",
                        suggestion=f"Use parameterized queries (prepared statements) to prevent SQL injection in '{p_name}'.",
                    )
                )
                continue

            # Check 2: Quote Balancing (param' breaks vs param'' fixes)
            pair_payload = f"{orig_val}''" if orig_val else "''"
            req_pair = _clone_and_mutate_param(request, p_type, p_name, pair_payload)
            resp_pair = _send(req_pair, session)

            break_differs = (
                resp_break.status_code != base_status
                or abs(resp_break.body_len - base_len) > max(30, int(base_len * 0.15))
                or _similarity(base_body, resp_break.body or "") < 0.85
            )

            if resp_pair and break_differs:
                pair_matches = (
                    resp_pair.status_code == base_status
                    and _similarity(base_body, resp_pair.body or "") >= 0.90
                )
                if pair_matches:
                    result.vulnerabilities.append(
                        SqliFinding(
                            param=p_name,
                            param_type=p_type,
                            injection_type="quote_balancing",
                            confidence="high",
                            payload=break_payload,
                            baseline_status=base_status,
                            payload_status=resp_break.status_code,
                            evidence=f"Syntax break '{break_payload}' caused status/content anomaly ({base_status} -> {resp_break.status_code}, len {base_len} -> {resp_break.body_len}), but balanced quotes '{pair_payload}' restored baseline (status {resp_pair.status_code}).",
                            suggestion=f"Parameter '{p_name}' escapes into a SQL string context. Parameterize the query.",
                        )
                    )
                    continue

            # Check 3: Status Anomaly on quote injection (e.g. 200 -> 500 / 404 / 503)
            if base_status == 200 and resp_break.status_code in (500, 502, 503):
                result.vulnerabilities.append(
                    SqliFinding(
                        param=p_name,
                        param_type=p_type,
                        injection_type="status_anomaly",
                        confidence="medium",
                        payload=break_payload,
                        baseline_status=base_status,
                        payload_status=resp_break.status_code,
                        evidence=f"Single quote injection '{break_payload}' triggered server error {resp_break.status_code} (baseline status {base_status}).",
                        suggestion=f"Inspect server logs for unhandled SQL exceptions on parameter '{p_name}'.",
                    )
                )
                continue

        # --- Test B: Arithmetic Evaluation (for numeric parameters) ---
        if is_numeric and num_val > 0:
            arith_expr = f"{num_val + 1}-1"
            req_arith = _clone_and_mutate_param(request, p_type, p_name, arith_expr)
            resp_arith = _send(req_arith, session)

            if resp_arith and resp_arith.status_code == base_status:
                sim = _similarity(base_body, resp_arith.body or "")
                if sim >= 0.95:
                    # Negative control test: evaluate (num_val + 10) to confirm it is not just static page
                    control_expr = f"{num_val + 99999}"
                    req_ctrl = _clone_and_mutate_param(request, p_type, p_name, control_expr)
                    resp_ctrl = _send(req_ctrl, session)

                    ctrl_differs = (
                        resp_ctrl is None
                        or resp_ctrl.status_code != base_status
                        or _similarity(base_body, resp_ctrl.body or "") < 0.90
                    )

                    if ctrl_differs:
                        result.vulnerabilities.append(
                            SqliFinding(
                                param=p_name,
                                param_type=p_type,
                                injection_type="arithmetic_evaluation",
                                confidence="confirmed",
                                payload=arith_expr,
                                baseline_status=base_status,
                                payload_status=resp_arith.status_code,
                                evidence=f"Arithmetic expression '{arith_expr}' evaluated on the backend and returned identical content to '{orig_val}' ({round(sim * 100)}% match), while control '{control_expr}' differed.",
                                suggestion=f"Numeric parameter '{p_name}' is concatenated directly into SQL without sanitization or parameter binding.",
                            )
                        )
                        continue

        # --- Test C: Boolean-based Differential Evaluation ---
        if is_numeric:
            true_payload = f"{orig_val} AND 1=1"
            false_payload = f"{orig_val} AND 1=2"
        else:
            true_payload = f"{orig_val}' AND '1'='1"
            false_payload = f"{orig_val}' AND '1'='2"

        req_true = _clone_and_mutate_param(request, p_type, p_name, true_payload)
        req_false = _clone_and_mutate_param(request, p_type, p_name, false_payload)

        resp_true = _send(req_true, session)
        resp_false = _send(req_false, session)

        if resp_true and resp_false:
            true_sim = _similarity(base_body, resp_true.body or "")
            false_sim = _similarity(base_body, resp_false.body or "")

            true_matches = resp_true.status_code == base_status and true_sim >= 0.85
            false_differs = (
                resp_false.status_code != base_status
                or abs(resp_false.body_len - base_len) > max(15, int(base_len * 0.10))
                or false_sim < 0.80
                or (true_sim - false_sim) >= 0.10
            )

            if true_matches and false_differs:
                result.vulnerabilities.append(
                    SqliFinding(
                        param=p_name,
                        param_type=p_type,
                        injection_type="boolean_differential",
                        confidence="high",
                        payload=false_payload,
                        baseline_status=base_status,
                        payload_status=resp_false.status_code,
                        evidence=f"Boolean TRUE '{true_payload}' matched baseline ({round(true_sim * 100)}% similarity), but FALSE '{false_payload}' altered response (status {resp_false.status_code}, {round(false_sim * 100)}% similarity, len {resp_false.body_len} vs baseline {base_len}).",
                        suggestion=f"Parameter '{p_name}' is susceptible to boolean-based blind SQL injection. Use parameterized queries.",
                    )
                )

    return result


__all__ = ["DB_ERRORS", "scan_sqli"]
