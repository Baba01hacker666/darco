# Mutation Engine

Mutations are the "Burp-style" request edits that make Darco useful to agents.
They are deliberately **small, composable transforms**. The smart fuzz engine
(`darco/fuzz.py`) builds variants on top of these primitives automatically.

Module: `darco/mutate.py`.

## Model

`Mutation` is a dataclass:

```python
@dataclass
class Mutation:
    op: str  # set_header | unset_header | set_param | unset_param |
    # flip_param | strip_session | set_body
    name: str = ""
    value: str = ""
    extra: dict = field(default_factory=dict)
```

`Mutation.describe()` produces the human-readable string that lands in
`request.mutations` (lineage).

## Transforms

| op | Behavior | Example |
| --- | --- | --- |
| `set_header` | Replace first header with matching name (case-insensitive) or append | `--set-header X-Admin: 1` |
| `unset_header` | Remove all headers with matching name | `--unset-header Authorization` |
| `set_param` | Replace matching query param or append; also sets the same-named form field if present | `--set-param user=admin` |
| `unset_param` | Remove matching query **and** form-field params | `--unset-param otp_code` |
| `flip_param` | Toggle a boolean-ish value (see below); flips the form field too | `--flip-param enabled` |
| `strip_session` | Set `request.session_stripped = True`; the engine then drops cookies + auth headers | `--strip-session` |
| `set_body` | Replace body with raw text; `@file` reads the file contents | `--set-body @payload.txt` |

### Flip semantics

`flip_value()` maps on `FLIP_MAP`:

```
true <-> false    1 <-> 0    yes <-> no    on <-> off
```

Case is preserved (TRUE → FALSE, No → Yes). Any other value raises
`DarcoError: cannot flip value ...`.

### `--modify-file`

A JSON array of ops for complex edits:

```json
[
  {"op": "set_header", "name": "Y", "value": "9"},
  {"op": "strip_session"},
  {"op": "flip_param", "name": "enabled"}
]
```

Parsed by `_parse_modify_file`; unknown ops raise `DarcoError`.

## Non-destructive + lineage

`apply_mutations(request, ops)`:

1. `request.model_copy(deep=True)` — the original is never touched.
2. Applies each op in order (later ops see earlier results).
3. Returns `(new_request, descriptions)`; `new_request.mutations` extends the
   base's list, so a chain of replays accumulates full history:
   `["set header X: 1", "set header X: 2"]`.

When sent via `send --from <id>`, the CLI sets `parent_id` on the copy before
mutating, so agents can walk: `0007 (stripped) ← 0003 (normal)`.

## Where mutations come from

- CLI flags on `darco send` (`--set-header`, `--unset-header`, `--set-param`,
  `--unset-param`, `--flip-param`, `--strip-session`, `--set-body`,
  `--modify-file`).
- `parse_mutation_ops()` normalizes the CLI flag shape into a `Mutation`
  list; `apply_mutations()` performs the work. The fuzz engine constructs
  `Mutation` lists programmatically on top of these — keep the two steps
  separate.
