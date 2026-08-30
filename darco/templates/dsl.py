"""Safe Nuclei-style DSL expression evaluator for template matchers.

Supports boolean expressions over response variables with ``&&`` / ``||`` /
``!`` / parentheses and comparisons (``==``, ``!=``, ``,`>` ``<``, ``>=``,
``<=``), plus string/number literals and helper functions:

* ``contains(haystack, needle)``, ``contains_any(haystack, s1, s2, ...)``
* ``startswith(s, prefix)``, ``endswith(s, suffix)``
* ``to_lower(s)``, ``to_upper(s)``, ``len(s)``
* ``regex(source, pattern)``

Variables injected by the engine: ``status_code``, ``content_length``,
``body``, ``header``, ``all``, ``url`` — plus any template variables.

No ``eval``: expressions are tokenized and evaluated by a small recursive
descent parser; unknown functions or variables simply evaluate to ``None``
(and comparisons against ``None`` are False).
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<string>'([^'\\]|\\.)*'|"([^"\\]|\\.)*")
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<op>==|!=|>=|<=|&&|\|\||[><!(),])
  | (?P<ident>[A-Za-z_][A-Za-z0-9_.]*)
    """,
    re.VERBOSE,
)


class DslError(ValueError):
    """Raised when a DSL expression cannot be parsed."""


def _tokenize(expr: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            raise DslError(f"unexpected character {expr[pos]!r} at {pos}")
        pos = m.end()
        kind = m.lastgroup or ""
        if kind == "ws":
            continue
        tokens.append((kind, m.group()))
    tokens.append(("eof", ""))
    return tokens


class _Parser:
    def __init__(self, tokens, variables: dict[str, Any]):
        self.tokens = tokens
        self.pos = 0
        self.vars = variables

    def _peek(self) -> tuple[str, str]:
        return self.tokens[self.pos]

    def _next(self) -> tuple[str, str]:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self):
        val = self._or()
        if self._peek()[0] != "eof":
            raise DslError(f"trailing token {self._peek()[1]!r}")
        return val

    def _or(self):
        val = self._and()
        while self._peek() == ("op", "||"):
            self._next()
            rhs = self._and()
            val = bool(val) or bool(rhs)
        return val

    def _and(self):
        val = self._cmp()
        while self._peek() == ("op", "&&"):
            self._next()
            rhs = self._cmp()
            val = bool(val) and bool(rhs)
        return val

    def _cmp(self):
        left = self._unary()
        tok_kind, tok_val = self._peek()
        if tok_kind == "op" and tok_val in ("==", "!=", ">", "<", ">=", "<="):
            self._next()
            right = self._unary()
            if left is None or right is None:
                return tok_val == "!="
            try:
                if tok_val == "==":
                    return left == right
                if tok_val == "!=":
                    return left != right
                if tok_val == ">":
                    return left > right
                if tok_val == "<":
                    return left < right
                if tok_val == ">=":
                    return left >= right
                return left <= right
            except TypeError:
                return False
        return left

    def _unary(self):
        if self._peek() == ("op", "!"):
            self._next()
            return not bool(self._unary())
        return self._primary()

    def _primary(self):
        kind, val = self._next()
        if (kind, val) == ("op", "("):
            inner = self._or()
            if self._next() != ("op", ")"):
                raise DslError("expected ')'")
            return inner
        if kind == "string":
            raw = val[1:-1]
            quote_char = val[0]
            if quote_char == "'":
                return raw.replace("\\'", "'").replace("\\\\", "\\")
            return raw.replace('\\"', '"').replace("\\\\", "\\")
        if kind == "number":
            return float(val) if "." in val else int(val)
        if kind == "ident":
            if self._peek() == ("op", "("):
                return self._call(val)
            return self._lookup(val)
        raise DslError(f"unexpected token {val!r}")

    def _call(self, fname: str):
        self._next()  # consume '('
        args = []
        if self._peek() != ("op", ")"):
            args.append(self._or())
            while self._peek() == ("op", ","):
                self._next()
                args.append(self._or())
        if self._next() != ("op", ")"):
            raise DslError(f"expected ')' closing call to {fname}()")
        return _FUNCTIONS.get(fname, lambda *a: None)(*args)

    def _lookup(self, name: str):
        if name.lower() == "true":
            return True
        if name.lower() == "false":
            return False
        if name in self.vars:
            return self.vars[name]
        # dotted lookups fall back to nested variable access
        cur: Any = self.vars
        for part in name.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur


_FUNCTIONS: dict[str, Any] = {}


def _fn(*names):
    def deco(f):
        for n in names:
            _FUNCTIONS[n] = f
        return f

    return deco


@_fn("contains")
def _contains(haystack, needle):
    return haystack is not None and needle is not None and str(needle) in str(haystack)


@_fn("contains_any")
def _contains_any(haystack, *needles):
    if haystack is None:
        return False
    text = str(haystack)
    flat = [s for n in needles for s in (n if isinstance(n, (list, tuple)) else [n])]
    return any(str(s) in text for s in flat)


@_fn("startswith")
def _startswith(s, prefix):
    return s is not None and str(s).startswith(str(prefix))


@_fn("endswith")
def _endswith(s, suffix):
    return s is not None and str(s).endswith(str(suffix))


@_fn("to_lower")
def _to_lower(s):
    return "" if s is None else str(s).lower()


@_fn("to_upper")
def _to_upper(s):
    return "" if s is None else str(s).upper()


@_fn("len")
def _len(v):
    return len(v) if v is not None else 0


@_fn("regex")
def _regex(source, pattern):
    if source is None:
        return False
    try:
        return re.search(str(pattern), str(source)) is not None
    except re.error:
        return False


def evaluate_dsl(expression: str, variables: dict[str, Any]) -> bool:
    """Evaluate a DSL expression to a boolean. Unparseable -> False."""
    try:
        return bool(_Parser(_tokenize(expression), variables).parse())
    except (DslError, RecursionError, TypeError):
        return False


__all__ = ["DslError", "evaluate_dsl"]
