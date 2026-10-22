"""Every rule must parse as valid Sigma, carry ATT&CK tags, and pass its fixtures:
fire on every malicious event and stay quiet on every benign one."""

import json
from pathlib import Path

import pytest
from sigma.rule import SigmaRule

from detectionlab.matcher import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "rules")
FIXTURES = ROOT / "tests" / "fixtures"


def events(rule, kind):
    folder = FIXTURES / rule.path.stem / kind
    return [(p.stem, json.loads(p.read_text())) for p in sorted(folder.glob("*.json"))]


def test_rules_exist():
    assert RULES, "no rules found"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_rule_is_valid_sigma(rule):
    parsed = SigmaRule.from_yaml(rule.path.read_text())
    assert parsed.title == rule.title


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_rule_metadata(rule):
    assert rule.techniques, "needs at least one attack.tXXXX tag"
    assert rule.tactics, "needs at least one ATT&CK tactic tag"
    assert rule.level in {"low", "medium", "high", "critical"}
    assert rule.falsepositives, "document known false positives"


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_fires_on_every_malicious_event(rule):
    cases = events(rule, "malicious")
    assert cases, f"add at least one fixture in tests/fixtures/{rule.path.stem}/malicious/"
    missed = [name for name, event in cases if not rule.matches(event)]
    assert not missed, f"rule missed: {missed}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_quiet_on_every_benign_event(rule):
    cases = events(rule, "benign")
    assert cases, f"add at least one fixture in tests/fixtures/{rule.path.stem}/benign/"
    false_positives = [name for name, event in cases if rule.matches(event)]
    assert not false_positives, f"false positives: {false_positives}"


def test_no_orphan_fixtures():
    rule_names = {r.path.stem for r in RULES}
    orphans = {p.name for p in FIXTURES.iterdir() if p.is_dir()} - rule_names
    assert not orphans, f"fixtures with no matching rule: {orphans}"


def test_coverage_doc_is_current():
    from scripts.coverage import render

    assert (ROOT / "docs" / "coverage.md").read_text() == render(RULES), (
        "docs/coverage.md is stale; run: python -m scripts.coverage"
    )
