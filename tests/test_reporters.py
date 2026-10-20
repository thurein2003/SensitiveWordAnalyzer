from __future__ import annotations

import json
from pathlib import Path

import pytest

from sensitive_word_analyzer.models import FileReport, ScanReport
from sensitive_word_analyzer.reporters import render_json, render_report, render_sarif, render_text
from sensitive_word_analyzer.rules import RuleSet
from sensitive_word_analyzer.scanner import Scanner


def _report_for(tmp_path: Path) -> tuple[RuleSet, ScanReport]:
    sample = tmp_path / "sample.txt"
    sample.write_text(
        "keylogger callback-server https://control.example.com/path\n", encoding="utf-8"
    )
    rules = RuleSet.default()
    return rules, Scanner(rules).scan(sample)


def test_text_report_contains_evidence_and_iocs(tmp_path: Path) -> None:
    _, report = _report_for(tmp_path)
    rendered = render_text(report)

    assert "[HIGH] collection.keylogging" in rendered
    assert "IOCs urls: https://control.example.com/path" in rendered
    assert "SHA-256" in rendered


def test_json_report_is_machine_readable(tmp_path: Path) -> None:
    _, report = _report_for(tmp_path)
    payload = json.loads(render_json(report))
    assert payload["summary"]["findings"] >= 2


def test_sarif_report_contains_rules_results_and_locations(tmp_path: Path) -> None:
    rules, report = _report_for(tmp_path)
    payload = json.loads(render_sarif(report, rules))
    run = payload["runs"][0]

    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"]
    assert run["results"][0]["locations"][0]["physicalLocation"]


def test_report_dispatch_rejects_unknown_format(tmp_path: Path) -> None:
    rules, report = _report_for(tmp_path)
    with pytest.raises(ValueError, match="unsupported report format"):
        render_report(report, "xml", rules)


def test_text_report_handles_clean_skipped_and_error_files() -> None:
    report = ScanReport(
        target="unsafe\x1btarget",
        started_at="now",
        duration_seconds=0,
        warnings=["limited\x00scan"],
        files=[
            FileReport(path="clean", size=0, file_type="text", entropy=0.0),
            FileReport(path="large", size=100, file_type="unknown", skipped_reason="limit"),
            FileReport(path="denied", size=0, file_type="unknown", error="permission\ndenied"),
        ],
    )

    rendered = render_text(report)

    assert "No rule matches." in rendered
    assert "SKIPPED: limit" in rendered
    assert "ERROR: permission\\x0adenied" in rendered
    assert "unsafe\\x1btarget" in rendered
    assert "WARNING: limited\\x00scan" in rendered
