"""A small Sigma rule evaluator for testing rules against JSON events.

This is not a SIEM backend. It exists so every rule in this repo can be checked in CI
against known-malicious and known-benign events, without standing up Splunk or Elastic.

Supported (the subset the rules here use, and the common core of Sigma):
  - selections as a mapping (all fields must match) or a list of mappings (any may match)
  - a list of values for a field = any value may match (or all, with |all)
  - modifiers: contains, startswith, endswith, re, all, exists
  - conditions: and, or, not, parentheses, "1 of sel*", "all of sel*", "1 of them"
  - case-insensitive string matching (Sigma's default); numbers compare as strings
  - dotted field names for nested JSON (userIdentity.type)
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MISSING = object()


def get_field(event: dict[str, Any], name: str) -> Any:
    if name in event:
        return event[name]
    value: Any = event
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            return MISSING
        value = value[part]
    return value


def _match_value(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if actual is MISSING or actual is None:
        return expected is None
    if expected is None:
        return False
    a, e = str(actual), str(expected)
    if "re" in modifiers:
        return re.search(e, a) is not None
    a, e = a.lower(), e.lower()
    if "contains" in modifiers:
        return e in a
    if "startswith" in modifiers:
        return a.startswith(e)
    if "endswith" in modifiers:
        return a.endswith(e)
    return a == e


def _match_field(event: dict[str, Any], key: str, expected: Any) -> bool:
    name, *modifiers = key.split("|")
    actual = get_field(event, name)
    if "exists" in modifiers:
        return (actual is not MISSING) == bool(expected)
    values = expected if isinstance(expected, list) else [expected]
    combine = all if "all" in modifiers else any
    return combine(_match_value(actual, v, modifiers) for v in values)


def _match_selection(event: dict[str, Any], selection: Any) -> bool:
    if isinstance(selection, list):
        return any(_match_selection(event, item) for item in selection)
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    raise ValueError(f"Unsupported selection: {selection!r}")


class _Condition:
    """Recursive-descent parser: expr := term (or term)*; term := factor (and factor)*."""

    TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")

    def __init__(self, text: str, results: dict[str, bool]):
        self.tokens = self.TOKEN.findall(text)
        self.pos = 0
        self.results = results

    def parse(self) -> bool:
        value = self._expr()
        if self.pos != len(self.tokens):
            raise ValueError(f"Unexpected token: {self.tokens[self.pos]!r}")
        return value

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _expr(self) -> bool:
        value = self._term()
        while self._peek() == "or":
            self._next()
            right = self._term()
            value = value or right
        return value

    def _term(self) -> bool:
        value = self._factor()
        while self._peek() == "and":
            self._next()
            right = self._factor()
            value = value and right
        return value

    def _factor(self) -> bool:
        token = self._peek()
        if token is None:
            raise ValueError("Condition ended early")
        if token == "not":
            self._next()
            return not self._factor()
        if token == "(":
            self._next()
            value = self._expr()
            if self._peek() != ")":
                raise ValueError("Missing closing parenthesis")
            self._next()
            return value
        if token in ("1", "all") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1] == "of":
            quantifier = self._next().lower()
            self._next()  # "of"
            pattern = self._next()
            names = list(self.results) if pattern == "them" else fnmatch.filter(self.results, pattern)
            if not names:
                raise ValueError(f"No selections match {pattern!r}")
            values = [self.results[n] for n in names]
            return all(values) if quantifier == "all" else any(values)
        name = self._next()
        if name not in self.results:
            raise ValueError(f"Unknown selection in condition: {name!r}")
        return self.results[name]


@dataclass
class Rule:
    path: Path
    title: str
    id: str
    level: str
    tags: list[str]
    logsource: dict[str, str]
    detection: dict[str, Any]
    falsepositives: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> Rule:
        data = yaml.safe_load(path.read_text())
        return cls(
            path=path,
            title=data["title"],
            id=str(data["id"]),
            level=data.get("level", ""),
            tags=[str(t) for t in data.get("tags", [])],
            logsource=data.get("logsource", {}),
            detection=data["detection"],
            falsepositives=data.get("falsepositives", []),
        )

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]

    @property
    def tactics(self) -> list[str]:
        return [
            t.split(".", 1)[1].replace("_", " ").replace("-", " ").title()
            for t in self.tags
            if t.startswith("attack.") and not re.fullmatch(r"attack\.[tsg]\d{4}(\.\d{3})?", t)
        ]

    def matches(self, event: dict[str, Any]) -> bool:
        selections = {k: v for k, v in self.detection.items() if k not in ("condition", "timeframe")}
        results = {name: _match_selection(event, sel) for name, sel in selections.items()}
        condition = self.detection["condition"]
        conditions = condition if isinstance(condition, list) else [condition]
        return any(_Condition(c, results).parse() for c in conditions)


def load_rules(root: Path) -> list[Rule]:
    return [Rule.load(p) for p in sorted(root.rglob("*.yml"))]
