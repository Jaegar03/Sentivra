"""A small SQL lexer for structural injection analysis.

This layer is independent of the regex signatures: rather than looking for
specific strings, it tokenizes the input and asks structural questions.

  * Does a quote close a string context and hand control to SQL keywords?
  * Is there an always-true comparison after OR (1=1, 'a'='a', 2>1)?
  * Does a comment cut off the rest of the query?
  * Is a second statement stacked after a semicolon?

An injected fragment only makes sense relative to where the application
pastes it, so the input is lexed three times, as it would appear inside an
unquoted value, a single-quoted string and a double-quoted string. The
most SQL-like interpretation wins (the same idea libinjection uses).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

KEYWORDS = frozenset({
    "select", "union", "insert", "update", "delete", "drop", "from", "where", "and", "or",
    "not", "xor", "like", "having", "group", "order", "by", "limit", "offset", "exec",
    "execute", "declare", "cast", "convert", "case", "when", "then", "else", "end",
    "null", "is", "in", "exists", "between", "into", "values", "table", "database",
    "truncate", "alter", "create", "waitfor", "delay", "all", "distinct", "set",
    "information_schema", "procedure", "shutdown", "true", "false",
})
FUNCTIONS = frozenset({
    "sleep", "pg_sleep", "benchmark", "concat", "char", "chr", "substring", "substr", "mid",
    "ascii", "ord", "extractvalue", "updatexml", "load_file", "version", "database", "user",
    "count", "floor", "rand", "if", "iif", "hex", "unhex", "md5", "length", "group_concat",
})
LOGICAL = frozenset({"and", "or", "xor", "||", "&&"})
BREAKOUT_FOLLOWERS = frozenset({"and", "or", "xor", "union", "having", "order", "group", "limit", "into", "procedure"})
STATEMENTS = frozenset({"select", "insert", "update", "delete", "drop", "create", "alter", "truncate", "exec", "execute", "declare", "shutdown"})

_TOKEN_RE = re.compile(
    r"""
    (?P<comment>--[^\n]*|\#[^\n]*|/\*.*?(?:\*/|$))
   |(?P<string>'(?:[^']|'')*'?|"(?:[^"]|"")*"?)
   |(?P<number>0x[0-9a-f]+\b|\d+(?:\.\d+)?)
   |(?P<variable>@@?[a-z_][a-z0-9_]*)
   |(?P<word>[a-z_][a-z0-9_$]*)
   |(?P<operator><=|>=|<>|!=|\|\||&&|[=<>+\-*/%!~^|&])
   |(?P<punct>[(),;.])
   |(?P<space>\s+)
   |(?P<other>.)
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass(frozen=True)
class Token:
    kind: str   # comment | string | number | variable | keyword | function | word | operator | punct | other
    value: str


@dataclass
class LexicalFindings:
    context: str
    fingerprint: str
    signals: dict[str, str] = field(default_factory=dict)  # signal name -> human explanation

    @property
    def strength(self) -> float:
        weights = {
            "string_breakout": 0.45,
            "numeric_breakout": 0.35,
            "tautology": 0.45,
            "comment_truncation": 0.25,
            "stacked_statement": 0.5,
            "union_structure": 0.45,
        }
        remaining = 1.0
        for name in self.signals:
            remaining *= 1.0 - weights.get(name, 0.2)
        return 1.0 - remaining


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    for m in _TOKEN_RE.finditer(text):
        kind = m.lastgroup
        value = m.group(0)
        if kind == "space":
            continue
        if kind == "word":
            if value in KEYWORDS:
                kind = "keyword"
            elif value in FUNCTIONS and m.end() < len(text) and text[m.end():].lstrip().startswith("("):
                kind = "function"
        tokens.append(Token(kind, value))
        if len(tokens) >= 200:  # bounded: long prose isn't an injection payload's structure
            break
    return tokens


_FP_CHAR = {"comment": "c", "string": "s", "number": "n", "variable": "v", "function": "f", "word": "b", "other": "?"}


def fingerprint(tokens: list[Token], length: int = 8) -> str:
    chars = []
    for t in tokens[:length]:
        if t.kind == "keyword":
            chars.append("&" if t.value in LOGICAL else "U" if t.value == "union" else "k")
        elif t.kind == "operator":
            chars.append("&" if t.value in LOGICAL else "o")
        elif t.kind == "punct":
            chars.append(t.value)
        else:
            chars.append(_FP_CHAR.get(t.kind, "?"))
    return "".join(chars)


def _literal_value(tok: Token) -> str | float | None:
    if tok.kind == "number":
        try:
            return float(int(tok.value, 16)) if tok.value.startswith("0x") else float(tok.value)
        except ValueError:
            return None
    if tok.kind == "string":
        body = tok.value[1:]
        if body.endswith(tok.value[0]) and len(tok.value) > 1:
            body = body[:-1]
        return body
    return None


def _is_tautology(left: Token, op: Token, right: Token) -> bool:
    lv, rv = _literal_value(left), _literal_value(right)
    if lv is None or rv is None:
        return False
    if op.value in ("=", "like"):
        return lv == rv
    if isinstance(lv, float) and isinstance(rv, float):
        return {"<": lv < rv, ">": lv > rv, "<=": lv <= rv, ">=": lv >= rv, "<>": lv != rv, "!=": lv != rv}.get(op.value, False)
    return op.value in ("<>", "!=") and lv != rv


def _analyze(tokens: list[Token], context: str) -> LexicalFindings:
    findings = LexicalFindings(context=context, fingerprint=fingerprint(tokens))
    if not tokens:
        return findings

    def is_sql(tok: Token) -> bool:
        return tok.kind in ("keyword", "function") or (tok.kind == "operator" and tok.value in LOGICAL)

    # 1. Breaking out of the surrounding context into SQL.
    if context != "unquoted" and tokens[0].kind == "string" and len(tokens) > 1:
        nxt = tokens[1]
        if (nxt.kind == "keyword" and nxt.value in BREAKOUT_FOLLOWERS) or (nxt.kind == "operator" and nxt.value in LOGICAL) \
                or (nxt.kind == "punct" and nxt.value in (";", ")")) or nxt.kind == "comment":
            findings.signals["string_breakout"] = (
                f"a quote closes the {context} string and is followed by '{nxt.value}'"
            )
    # A number followed by OR/AND/UNION and then more SQL ("1 union select",
    # "1 and sleep(5)"). "5 or 6 people" doesn't qualify: after "or" comes
    # another number, not SQL. The tautology check below covers "1 or 1=1".
    if context == "unquoted" and len(tokens) > 2 and tokens[0].kind == "number" \
            and tokens[1].kind == "keyword" and tokens[1].value in BREAKOUT_FOLLOWERS and is_sql(tokens[2]):
        findings.signals["numeric_breakout"] = (
            f"value '{tokens[0].value}' is followed by SQL '{tokens[1].value} {tokens[2].value}'"
        )

    # 2. Tautologies after a logical operator: OR 1=1, OR 'a'='a', OR 2>1.
    comparisons = ("=", "like", "<", ">", "<=", ">=", "<>", "!=")
    for i in range(len(tokens) - 3):
        logical, left, op, right = tokens[i:i + 4]
        if logical.value in ("or", "||", "xor") and op.value in comparisons and _is_tautology(left, op, right):
            findings.signals["tautology"] = (
                f"always-true condition: {logical.value} {left.value} {op.value} {right.value}"
            )
            break

    # 3. Comment truncating the rest of the query: either right after the
    # quote that escaped the string (admin'--) or after SQL tokens. A dash
    # pair in prose ("It's great -- really") has neither.
    for i, tok in enumerate(tokens):
        if tok.kind != "comment" or i == 0:
            continue
        directly_after_breakout = i == 1 and context != "unquoted" and tokens[0].kind == "string"
        if directly_after_breakout or any(is_sql(t) for t in tokens[:i]):
            findings.signals["comment_truncation"] = f"comment '{tok.value[:12]}' truncates the rest of the query"
            break

    # 4. A second statement after a semicolon.
    for i, tok in enumerate(tokens[:-1]):
        if tok.value == ";" and tokens[i + 1].kind == "keyword" and tokens[i + 1].value in STATEMENTS:
            findings.signals["stacked_statement"] = f"'; {tokens[i + 1].value}' starts a second statement"
            break

    # 5. UNION ... SELECT structure.
    values = [t.value for t in tokens]
    if "union" in values:
        u = values.index("union")
        if "select" in values[u + 1:u + 4]:
            findings.signals["union_structure"] = "UNION followed by SELECT"
    return findings


def analyze(text: str) -> LexicalFindings:
    """Lex `text` in each of the three contexts; return the most SQL-like reading."""
    readings = [
        _analyze(tokenize(text), "unquoted"),
        _analyze(tokenize("'" + text), "single-quoted"),
        _analyze(tokenize('"' + text), "double-quoted"),
    ]
    return max(readings, key=lambda f: (f.strength, len(f.signals)))
