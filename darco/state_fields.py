"""Opaque framework state fields that automated audits should not mutate.

ASP.NET Web Forms (and other server frameworks) protect hidden form state with
MAC signatures. Tampering with those fields produces framework validation
errors (e.g. "The state information is invalid for this page and might be
corrupted") that look like SQLi or XSS findings but are pure framework
behavior. Skipping them by default keeps scans on ASP.NET targets free of
false positives; pass ``include_state_fields=True`` to audit them anyway.
"""

from __future__ import annotations

import re

# Hidden state / anti-CSRF fields skipped by default in SQLi/XSS/fuzz audits.
STATE_FIELD_NAMES = frozenset(
    {
        # ASP.NET Web Forms viewstate machinery
        "__VIEWSTATE",
        "__VIEWSTATEGENERATOR",
        "__VIEWSTATEENCRYPTED",
        "__EVENTVALIDATION",
        "__EVENTTARGET",
        "__EVENTARGUMENT",
        "__LASTFOCUS",
        "__ASYNCPOST",
        "__CALLBACKID",
        "__CALLBACKPARAM",
        # Common framework anti-CSRF tokens
        "_CSRF",
        "CSRF_TOKEN",
        "CSRFMIDDLEWARETOKEN",
        "AUTHENTICITY_TOKEN",
        "__REQUESTVERIFICATIONTOKEN",
        "XSRF-TOKEN",
        "X-CSRF-TOKEN",
    }
)

# Response-body signatures that indicate a framework state-validation error
# page rather than an application or database error.
_STATE_ERROR_PATTERNS = (
    re.compile(r"the state information is invalid for this page", re.IGNORECASE),
    re.compile(r"validation of viewstate mac failed", re.IGNORECASE),
    re.compile(
        r"the required anti-forgery (form field|cookie|token)", re.IGNORECASE
    ),
)


def is_state_field(name: str) -> bool:
    """Return True if a parameter is an opaque framework state field."""
    return name in STATE_FIELD_NAMES or name.upper() in STATE_FIELD_NAMES


def is_state_validation_error(body: str) -> bool:
    """Return True if a response body is a framework state-validation error page."""
    return any(pat.search(body or "") for pat in _STATE_ERROR_PATTERNS)
