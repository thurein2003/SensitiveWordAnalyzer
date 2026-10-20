import pytest

from sensitive_word_analyzer.models import FileReport, Finding, ScanReport, Severity


def test_severity_parser_and_rank() -> None:
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.CRITICAL.rank > Severity.MEDIUM.rank


def test_severity_parser_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="invalid severity"):
        Severity.parse("urgent")


def test_scan_report_summarizes_results() -> None:
    finding = Finding(
        rule_id="test.rule",
        rule_name="Test rule",
        category="test",
        severity=Severity.HIGH,
        description="Test finding",
        match="match",
        snippet="a match here",
        source="decoded-text",
        line=3,
    )
    report = ScanReport(
        target="/tmp/sample",
        started_at="2026-01-01T00:00:00+00:00",
        duration_seconds=0.1,
        files=[
            FileReport(path="clean", size=1, file_type="text"),
            FileReport(path="finding", size=2, file_type="text", findings=[finding]),
            FileReport(path="large", size=3, file_type="unknown", skipped_reason="too large"),
            FileReport(path="error", size=0, file_type="unknown", error="denied"),
        ],
    )

    assert report.scanned_count == 2
    assert report.skipped_count == 1
    assert report.error_count == 1
    assert report.finding_count == 1
    assert report.highest_severity is Severity.HIGH
    assert report.to_dict()["summary"]["files_discovered"] == 4


def test_empty_report_has_no_highest_severity() -> None:
    report = ScanReport(target="empty", started_at="now", duration_seconds=0)
    assert report.highest_severity is None
