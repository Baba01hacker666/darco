"""Darco CLI, split into focused modules.

Layout:

* ``_group``    — root ``cli`` click group (global options), ``main()`` entrypoint
* ``_output``   -- JSON/markdown/table emission helpers (``--format`` contract)
* ``_context``  -- workspace resolution helpers
* ``_rawio``    -- raw HTTP request/response serialization
* ``_oneshot``  -- shared on-the-fly request building used by send/fuzz/scanners
* ``cmd_*``     -- one module per command family, registered on import

Public surface (used by tests / entry points): ``cli``, ``main``.
"""

# Importing the command modules registers every @cli.command on the group.
from . import (  # noqa: F401
    cmd_auth,
    cmd_basic,
    cmd_cors,
    cmd_crawl,
    cmd_fuzz,
    cmd_ingest,
    cmd_js,
    cmd_openapi,
    cmd_origin,
    cmd_proxy,
    cmd_recon,
    cmd_redirect,
    cmd_report,
    cmd_send,
    cmd_sqli,
    cmd_template,
    cmd_transport,
    cmd_traversal,
    cmd_waf_bypass,
    cmd_xss,
)
from ._context import _find_workspace  # noqa: F401
from ._group import cli, main

# Backwards-compatible re-exports (tests reach into these).
from ._output import _table_from_json  # noqa: F401

__all__ = ["cli", "main"]
