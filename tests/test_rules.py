from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from sensitive_word_analyzer.models import Severity
from sensitive_word_analyzer.rules import RuleSet, RuleValidationError


def _pack(**overrides: Any) -> Dict[str, Any]:
    rule: Dict[str, Any] = {
        "id": "test.rule",
        "name": "Test rule",
        "description": "Used by tests.",
        "category": "test",
        "severity": "medium",
        "patterns": ["literal", {"kind": "regex", "expression": "te(?:st)+"}],
    }
    rule.update(overrides)
    return {"name": "test-pack", "rules": [rule]}


def test_default_rules_load_and_compile() -> None:
    rules = RuleSet.default()
    assert rules.name == "swa-default"
    assert len(rules.rules) == 10
    assert len(rules.compiled) >= len(rules.rules)


def test_custom_rule_file_loads(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(_pack()), encoding="utf-8")
    rules = RuleSet.from_file(path)

    assert rules.rules[0].severity is Severity.MEDIUM
    assert rules.rules[0].patterns[0].kind == "literal"


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"name": "test"},
        {"name": "", "rules": []},
        {"name": "test", "rules": ["not-an-object"]},
        _pack(id="bad id"),
        _pack(name=4),
        _pack(severity="urgent"),
        _pack(patterns=[]),
        _pack(patterns=[{}]),
        _pack(patterns=[{"expression": "x" * 513}]),
        _pack(patterns=[{"expression": "x", "case_sensitive": "yes"}]),
        _pack(patterns=[{"expression": "x", "kind": "glob"}]),
        _pack(patterns=[{"expression": "(", "kind": "regex"}]),
    ],
)
def test_invalid_rule_packs_are_rejected(payload: Any) -> None:
    with pytest.raises(RuleValidationError):
        RuleSet.from_mapping(payload)


def test_duplicate_rule_ids_are_rejected() -> None:
    payload = _pack()
    payload["rules"].append(dict(payload["rules"][0]))
    with pytest.raises(RuleValidationError, match="unique"):
        RuleSet.from_mapping(payload)


def test_missing_rule_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuleValidationError, match="could not read"):
        RuleSet.from_file(tmp_path / "missing.json")
