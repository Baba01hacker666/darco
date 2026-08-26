# Scan Plugins

Darco's active scanners dispatch to registered plugins at well-defined hook
points, so new attack-surface checks (XML/XXE, IDOR, path traversal, SSRF,
stored XSS, …) can be added as self-contained modules instead of growing
`darco/sqli.py`.

## Registry & lifecycle

- `darco/plugins/__init__.py` — `ScanPlugin` base class, `_REGISTRY`,
  `register_plugin`, `registered_plugins()`, `active_plugins()`.
- Built-in plugins live in `darco/plugins/` and register themselves when the
  package is imported.
- `darco plugins` lists every registered plugin (name + description).
- `darco sql` / `darco sqli` accept `--plugin NAME` (run only these) and
  `--skip-plugin NAME` (disable one); both are repeatable.

## Hook points

```python
class ScanPlugin:
    name: str = ""
    description: str = ""

    def collect_params(self, request, include_state_fields=False, param_filter=None):
        # -> list[(param_type, name, value)] contributed to the sqli scan
        return []

    def after_param(self, request, session, param_type, param_name,
                    orig_val, baseline, result):
        # channel-specific probes/findings after the core per-param tests
        pass

    def after_scan(self, request, session, result):
        # summary findings or cleanup, once per scan
        pass
```

`scan_sqli` gathers parameters from query/form/json sources **plus** every
plugin's `collect_params`, runs its core tests (quote balancing, arithmetic
evaluation, boolean differential, OR-logic) on all of them, then calls
`after_param` for each parameter and `after_scan` once at the end.

## Built-in: `xml_inject`

Detects endpoints that parse XML request bodies and expand character
references, then tests entity-encoded SQLi that a raw-byte WAF never sees.

**How it knows the endpoint is XML (behavioral probes):**

| Probe | Request | Confirms |
| --- | --- | --- |
| `unclosed_tag` | `<storeId>1` (truncated) | XML parse error -> server parses XML |
| `numeric_ref` | `<storeId>&#x31;</storeId>` | char ref decodes to `1`; response matches baseline — the smoking gun |
| `undefined_entity` | `<storeId>&abc;</storeId>` | hard parse failure, not "bad input" |
| `non_xml` | `storeId=1` form body | endpoint rejects non-XML outright |

If the numeric-ref probe returns the same content as the literal value, an XML
parser decoded the entities — so a payload encoded as `&#x55;&#x4e;...`
(=`UNION`) reaches SQL decoded while the WAF only ever saw `&#x..;` tokens.

**Findings produced:**

- `xml_entity_decoding` — endpoint parses XML and expands character refs
  (attack surface fact; includes a replay curl).
- `xml_encoded_sqli` — OR/boolean differential through the entity-encoded
  channel; `confidence: confirmed` when the raw payload was 403-blocked
  (WAF bypass proven), `high` otherwise.

**Workflow:**

```bash
darco ingest curl -- \
  "curl -i -X POST 'https://target/product/stock' \
   -H 'Content-Type: application/xml' \
   --data-binary '<storeId>1</storeId>'"
darco sql --from 0001 --insecure
darco plugins                 # list available plugins
```

The finding's `curl` field is a copy-paste replay command for manual
verification (shown as **Verify manually** in markdown output).

## Adding a plugin

1. Create `darco/plugins/<name>.py` subclassing `ScanPlugin` and decorated
   with `@register_plugin`.
2. Import it from `darco/plugins/__init__.py` so it registers at startup.
3. Add tests in `tests/test_plugins.py` (dispatch, filtering, findings).
4. Run `.venv/bin/python -m pytest -q` before finishing.

Keep low-level helpers out of plugins: `darco/xmlinject.py` holds the XML
parsing/encoding/probe primitives, and `xml_inject` (the plugin) only wires
them into the scan hooks.
