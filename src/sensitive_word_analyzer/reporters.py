"""Human-readable, JSON, and SARIF 2.1.0 report rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .models import Finding, ScanReport, Severity
from .rules import RuleSet


def _safe(value: str) -> str:
    rendered: List[str] = []
    for character in value:
        if character.isprintable():
            rendered.append(character)
        elif ord(character) <= 0xFF:
            rendered.append(f"\\x{ord(character):02x}")
        else:
            rendered.append(f"\\u{ord(character):04x}")
    return "".join(rendered)


def render_text(report: ScanReport) -> str:
    highest = report.highest_severity
    lines = [
        "Sensitive Word Analyzer",
        "=" * 23,
        f"Target: {_safe(report.target)}",
        f"Started: {report.started_at}",
        f"Duration: {report.duration_seconds:.3f}s",
        "",
        (
            f"Summary: {report.scanned_count} scanned, {report.skipped_count} skipped, "
            f"{report.error_count} errors, {len(report.warnings)} warnings, "
            f"{report.finding_count} findings, "
            f"highest severity: {highest.value if highest else 'none'}"
        ),
    ]

    for warning in report.warnings:
        lines.append(f"WARNING: {_safe(warning)}")

    for file in report.files:
        lines.extend(("", _safe(file.path), "-" * min(80, max(8, len(file.path)))))
        if file.skipped_reason:
            lines.append(f"SKIPPED: {_safe(file.skipped_reason)}")
            continue
        if file.error:
            lines.append(f"ERROR: {_safe(file.error)}")
            continue

        sha256 = file.hashes.get("sha256", "unavailable")
        entropy = f"{file.entropy:.4f}" if file.entropy is not None else "unavailable"
        lines.append(
            f"Type: {file.file_type} | Size: {file.size} bytes | "
            f"Entropy: {entropy} | SHA-256: {sha256}"
        )
        if not file.findings:
            lines.append("No rule matches.")
        for finding in file.findings:
            location = f"line {finding.line}" if finding.line else finding.source
            lines.append(
                f"[{finding.severity.value.upper()}] {finding.rule_id} ({location}): "
                f"{_safe(finding.match)}"
            )
            lines.append(f"  {_safe(finding.snippet)}")

        for indicator_type, values in file.indicators.items():
            lines.append(f"IOCs {indicator_type}: " + ", ".join(_safe(value) for value in values))

    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def _sarif_level(severity: Severity) -> str:
    if severity.rank >= Severity.HIGH.rank:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_location(path: str, finding: Finding) -> Dict[str, Any]:
    artifact: Dict[str, Any] = {"uri": Path(path).absolute().as_uri()}
    physical: Dict[str, Any] = {"artifactLocation": artifact}
    if finding.line:
        physical["region"] = {"startLine": finding.line}
    return {"physicalLocation": physical}


def render_sarif(report: ScanReport, rules: RuleSet) -> str:
    used_rule_ids = {finding.rule_id for file in report.files for finding in file.findings}
    sarif_rules = [
        {
            "id": rule.rule_id,
            "name": rule.name.replace(" ", ""),
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "properties": {
                "category": rule.category,
                "security-severity": str(rule.severity.rank * 2.5),
                "severity": rule.severity.value,
            },
        }
        for rule in rules.rules
        if rule.rule_id in used_rule_ids
    ]
    results = [
        {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": f"{finding.description} Matched: {_safe(finding.match)}"},
            "locations": [_sarif_location(file.path, finding)],
            "properties": {
                "category": finding.category,
                "severity": finding.severity.value,
                "source": finding.source,
                "snippet": _safe(finding.snippet),
            },
        }
        for file in report.files
        for finding in file.findings
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sensitive Word Analyzer",
                        "informationUri": ("https://github.com/thurein2003/SensitiveWordAnalyzer"),
                        "rules": sarif_rules,
                        "version": "1.0.0",
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": report.error_count == 0,
                        "properties": report.to_dict()["summary"],
                    }
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_report(report: ScanReport, output_format: str, rules: RuleSet) -> str:
    if output_format == "text":
        return render_text(report)
    if output_format == "json":
        return render_json(report)
    if output_format == "sarif":
        return render_sarif(report, rules)
    raise ValueError(f"unsupported report format: {output_format}")
