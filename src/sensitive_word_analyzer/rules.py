"""Rule-pack loading, validation, and regular-expression compilation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Pattern, Tuple

from .models import Severity


@dataclass(frozen=True)
class PatternSpec:
    expression: str
    kind: str = "literal"
    case_sensitive: bool = False


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    description: str
    category: str
    severity: Severity
    patterns: Tuple[PatternSpec, ...]


@dataclass(frozen=True)
class CompiledPattern:
    rule: Rule
    expression: Pattern[str]


class RuleValidationError(ValueError):
    """Raised when a rule pack is malformed or unsafe to load."""


class RuleSet:
    """An immutable, validated collection of analysis rules."""

    def __init__(self, rules: Iterable[Rule], name: str = "custom") -> None:
        rule_list = tuple(rules)
        if not rule_list:
            raise RuleValidationError("a rule pack must contain at least one rule")

        identifiers = [rule.rule_id for rule in rule_list]
        if len(set(identifiers)) != len(identifiers):
            raise RuleValidationError("rule ids must be unique")

        self.name = name
        self.rules = rule_list
        self.compiled = tuple(compiled for rule in rule_list for compiled in self._compile(rule))

    @classmethod
    def default(cls) -> "RuleSet":
        rule_text = (
            resources.files("sensitive_word_analyzer.data")
            .joinpath("default_rules.json")
            .read_text(encoding="utf-8")
        )
        return cls.from_mapping(json.loads(rule_text))

    @classmethod
    def from_file(cls, path: Path) -> "RuleSet":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise RuleValidationError(f"could not read rule pack {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuleValidationError(f"invalid JSON in rule pack {path}: {exc}") from exc
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "RuleSet":
        if not isinstance(payload, Mapping):
            raise RuleValidationError("rule pack root must be a JSON object")

        name = payload.get("name", "custom")
        raw_rules = payload.get("rules")
        if not isinstance(name, str) or not name.strip():
            raise RuleValidationError("rule pack name must be a non-empty string")
        if not isinstance(raw_rules, list):
            raise RuleValidationError("rule pack 'rules' must be a list")

        rules = [cls._parse_rule(item, index) for index, item in enumerate(raw_rules)]
        return cls(rules, name=name.strip())

    @staticmethod
    def _parse_rule(payload: Any, index: int) -> Rule:
        location = f"rules[{index}]"
        if not isinstance(payload, Mapping):
            raise RuleValidationError(f"{location} must be an object")

        required = ("id", "name", "description", "category", "severity", "patterns")
        missing = [key for key in required if key not in payload]
        if missing:
            raise RuleValidationError(f"{location} is missing: {', '.join(missing)}")

        strings: Dict[str, str] = {}
        for key in required[:-1]:
            value = payload[key]
            if not isinstance(value, str) or not value.strip():
                raise RuleValidationError(f"{location}.{key} must be a non-empty string")
            strings[key] = value.strip()

        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", strings["id"]):
            raise RuleValidationError(f"{location}.id has an invalid format")

        try:
            severity = Severity.parse(strings["severity"])
        except ValueError as exc:
            raise RuleValidationError(f"{location}.severity: {exc}") from exc

        raw_patterns = payload["patterns"]
        if not isinstance(raw_patterns, list) or not raw_patterns:
            raise RuleValidationError(f"{location}.patterns must be a non-empty list")
        patterns = tuple(
            RuleSet._parse_pattern(item, f"{location}.patterns[{pattern_index}]")
            for pattern_index, item in enumerate(raw_patterns)
        )

        return Rule(
            rule_id=strings["id"],
            name=strings["name"],
            description=strings["description"],
            category=strings["category"],
            severity=severity,
            patterns=patterns,
        )

    @staticmethod
    def _parse_pattern(payload: Any, location: str) -> PatternSpec:
        expression: Any
        kind: Any
        case_sensitive: Any
        if isinstance(payload, str):
            expression = payload
            kind = "literal"
            case_sensitive = False
        elif isinstance(payload, Mapping):
            expression = payload.get("expression")
            kind = payload.get("kind", "literal")
            case_sensitive = payload.get("case_sensitive", False)
        else:
            raise RuleValidationError(f"{location} must be a string or object")

        if not isinstance(expression, str) or not expression:
            raise RuleValidationError(f"{location}.expression must be a non-empty string")
        if len(expression) > 512:
            raise RuleValidationError(f"{location}.expression exceeds 512 characters")
        if kind not in {"literal", "regex"}:
            raise RuleValidationError(f"{location}.kind must be 'literal' or 'regex'")
        if not isinstance(case_sensitive, bool):
            raise RuleValidationError(f"{location}.case_sensitive must be a boolean")
        return PatternSpec(expression=expression, kind=kind, case_sensitive=case_sensitive)

    @staticmethod
    def _compile(rule: Rule) -> List[CompiledPattern]:
        compiled: List[CompiledPattern] = []
        for pattern in rule.patterns:
            source = (
                re.escape(pattern.expression) if pattern.kind == "literal" else pattern.expression
            )
            flags = 0 if pattern.case_sensitive else re.IGNORECASE
            try:
                expression = re.compile(source, flags)
            except re.error as exc:
                raise RuleValidationError(
                    f"rule {rule.rule_id!r} contains an invalid regex: {exc}"
                ) from exc
            compiled.append(CompiledPattern(rule=rule, expression=expression))
        return compiled

    def minimum(self, severity: Severity) -> "RuleSet":
        return RuleSet(
            (rule for rule in self.rules if rule.severity.rank >= severity.rank),
            name=self.name,
        )
