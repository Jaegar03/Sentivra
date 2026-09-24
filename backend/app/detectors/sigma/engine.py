"""A Sigma rule engine for normalized Sentivra events.

Implements the parts of the Sigma specification that single-event rules
use:
  * Selections: a map means every field must match (AND); a list of maps
    means any map may match (OR); a list of values means any value may
    match, unless the `all` modifier is used.
  * Value matching: case-insensitive with `*` / `?` wildcards by default,
    plus the modifiers contains, startswith, endswith, all, re (with i/m/s
    flags), cidr, exists, cased, gt/gte/lt/lte and windash.
  * Keyword searches: a plain list of strings, matched against every field.
  * Conditions: and / or / not, parentheses, `1 of X*`, `all of X*`,
    `1 of them`, `all of them`, and lists of conditions (OR).

Anything else (aggregations such as `| count() by`, base64 modifiers,
placeholders, correlation rules) makes the rule *unsupported*. Unsupported
rules are listed with the reason via GET /api/v1/rules, so coverage gaps
are visible, and they never run half-evaluated.

Regexes from rules run through the `regex` module with a timeout, like
every other rule pattern in Sentivra.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import regex
import yaml

from app.core.config import get_settings

logger = logging.getLogger("sentivra.sigma")

Fields = dict[str, Any]
Matcher = Callable[[Fields], bool]

_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "exists",
                        "cased", "gt", "gte", "lt", "lte", "windash"}


class UnsupportedRule(Exception):
    pass


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    status: str
    description: str
    logsource: dict[str, str]
    tags: list[str]
    falsepositives: list[str]
    path: str
    matcher: Matcher = field(repr=False)


@dataclass
class RuleLoadReport:
    loaded: list[SigmaRule] = field(default_factory=list)
    unsupported: list[dict[str, str]] = field(default_factory=list)


# ---- value matching ----------------------------------------------------------


def _wildcard_to_regex(pattern: str) -> str:
    """Sigma wildcards (* ?) to a regex, honoring backslash escapes."""
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(regex.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else regex.escape(ch))
        i += 1
    return "".join(out)


def _string_matcher(value: str, modifiers: list[str]) -> Callable[[str], bool]:
    flags = regex.DOTALL
    if "cased" not in modifiers:
        flags |= regex.IGNORECASE
    timeout = get_settings().regex_timeout_s

    if "re" in modifiers:
        re_flags = 0 if "i" not in modifiers else regex.IGNORECASE
        re_flags |= regex.MULTILINE if "m" in modifiers else 0
        re_flags |= regex.DOTALL if "s" in modifiers else 0
        compiled = regex.compile(value, re_flags)
        return lambda s: compiled.search(s, timeout=timeout) is not None

    body = _wildcard_to_regex(value)
    if "windash" in modifiers:
        # "-x" in a rule should also match "/x" and the Unicode dashes Windows accepts.
        body = body.replace(regex.escape("-"), "[-/–—―]")
    if "contains" in modifiers:
        body = f".*{body}.*"
    elif "startswith" in modifiers:
        body = f"{body}.*"
    elif "endswith" in modifiers:
        body = f".*{body}"
    compiled = regex.compile(f"^{body}$", flags)
    return lambda s: compiled.search(s, timeout=timeout) is not None


def _value_matcher(value: Any, modifiers: list[str]) -> Callable[[Any], bool]:
    if value is None:
        return lambda v: v in (None, "")
    if "cidr" in modifiers:
        net = ipaddress.ip_network(str(value), strict=False)

        def in_cidr(v: Any) -> bool:
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False

        return in_cidr
    numeric = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}
    for mod, op in numeric.items():
        if mod in modifiers:
            bound = float(value)

            def compare(v: Any, op=op, bound=bound) -> bool:
                try:
                    return op(float(v), bound)
                except (TypeError, ValueError):
                    return False

            return compare
    if isinstance(value, bool):
        return lambda v: str(v).lower() == str(value).lower()
    if isinstance(value, (int, float)) and not modifiers:
        return lambda v: str(v) == str(value)
    match = _string_matcher(str(value), modifiers)
    return lambda v: v is not None and match(str(v))


def _field_matcher(key: str, values: Any) -> Matcher:
    name, *modifiers = key.split("|")
    unknown = [m for m in modifiers if m not in _SUPPORTED_MODIFIERS]
    if unknown:
        raise UnsupportedRule(f"modifier(s) {unknown} on field {name!r}")
    if "exists" in modifiers:
        want = bool(values)
        return lambda f: (f.get(name) not in (None, "")) == want
    items = values if isinstance(values, list) else [values]
    matchers = [_value_matcher(v, modifiers) for v in items]
    combine = all if "all" in modifiers else any

    def match(f: Fields) -> bool:
        actual = f.get(name)
        return combine(m(actual) for m in matchers)

    return match


def _search_matcher(definition: Any) -> Matcher:
    if isinstance(definition, dict):
        parts = [_field_matcher(k, v) for k, v in definition.items()]
        return lambda f: all(p(f) for p in parts)
    if isinstance(definition, list) and all(isinstance(d, dict) for d in definition):
        options = [_search_matcher(d) for d in definition]
        return lambda f: any(o(f) for o in options)
    if isinstance(definition, list):  # keyword search: any value, any field
        keywords = [_string_matcher(str(k), ["contains"]) for k in definition]
        return lambda f: any(kw(str(v)) for v in f.values() if v not in (None, "") for kw in keywords)
    raise UnsupportedRule(f"search definition of type {type(definition).__name__}")


# ---- condition parsing -------------------------------------------------------


class _ConditionParser:
    def __init__(self, text: str, searches: dict[str, Matcher]) -> None:
        if "|" in text:
            raise UnsupportedRule("aggregation in condition (e.g. '| count()')")
        self.tokens = text.replace("(", " ( ").replace(")", " ) ").split()
        self.pos = 0
        self.searches = searches

    def parse(self) -> Matcher:
        result = self._or()
        if self.pos != len(self.tokens):
            raise UnsupportedRule(f"unexpected token {self.tokens[self.pos]!r} in condition")
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _or(self) -> Matcher:
        parts = [self._and()]
        while self._peek() == "or":
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda f, ps=parts: any(p(f) for p in ps))

    def _and(self) -> Matcher:
        parts = [self._not()]
        while self._peek() == "and":
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda f, ps=parts: all(p(f) for p in ps))

    def _not(self) -> Matcher:
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda f: not inner(f)
        return self._atom()

    def _atom(self) -> Matcher:
        tok = self._peek()
        if tok is None:
            raise UnsupportedRule("condition ended unexpectedly")
        if tok == "(":
            self._take()
            inner = self._or()
            if self._peek() != ")":
                raise UnsupportedRule("unbalanced parentheses in condition")
            self._take()
            return inner
        if tok in ("1", "all", "any") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            quantifier = self._take().lower()
            self._take()  # "of"
            target = self._take()
            names = list(self.searches) if target.lower() == "them" else fnmatch.filter(self.searches, target)
            if not names:
                raise UnsupportedRule(f"'{quantifier} of {target}' matches no search identifier")
            group = [self.searches[n] for n in names]
            if quantifier == "all":
                return lambda f: all(g(f) for g in group)
            return lambda f: any(g(f) for g in group)
        name = self._take()
        if name not in self.searches:
            raise UnsupportedRule(f"condition references unknown search {name!r}")
        return self.searches[name]


def compile_detection(detection: dict) -> Matcher:
    detection = dict(detection)
    condition = detection.pop("condition", None)
    detection.pop("timeframe", None)
    if condition is None:
        raise UnsupportedRule("no condition")
    searches = {name: _search_matcher(defn) for name, defn in detection.items()}
    conditions = condition if isinstance(condition, list) else [condition]
    compiled = [_ConditionParser(str(c), searches).parse() for c in conditions]
    return compiled[0] if len(compiled) == 1 else (lambda f: any(c(f) for c in compiled))


# ---- loading -----------------------------------------------------------------


def load_rules(directory: Path) -> RuleLoadReport:
    report = RuleLoadReport()
    for path in sorted(list(directory.rglob("*.yml")) + list(directory.rglob("*.yaml"))):
        rel = str(path.relative_to(directory))
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            report.unsupported.append({"path": rel, "reason": f"invalid YAML: {exc}"})
            continue
        if len(docs) != 1 or not isinstance(docs[0], dict):
            report.unsupported.append({"path": rel, "reason": "multi-document or non-mapping rule files"})
            continue
        doc = docs[0]
        if "correlation" in doc:
            report.unsupported.append({"path": rel, "reason": "correlation rules"})
            continue
        try:
            matcher = compile_detection(doc.get("detection") or {})
        except (UnsupportedRule, regex.error, ValueError) as exc:
            report.unsupported.append({"path": rel, "reason": str(exc), "title": doc.get("title", "")})
            continue
        report.loaded.append(SigmaRule(
            id=str(doc.get("id", rel)),
            title=str(doc.get("title", rel)),
            level=str(doc.get("level", "medium")).lower(),
            status=str(doc.get("status", "experimental")).lower(),
            description=str(doc.get("description", "")).strip(),
            logsource={k: str(v).lower() for k, v in (doc.get("logsource") or {}).items()},
            tags=[str(t).lower() for t in doc.get("tags") or []],
            falsepositives=[str(x) for x in doc.get("falsepositives") or []],
            path=rel,
            matcher=matcher,
        ))
    return report
