from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from sensitive_word_analyzer.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, _byte_size, main


@pytest.mark.parametrize(
    ("value", "expected"),
    [("10", 10), ("2KB", 2_000), ("2KiB", 2_048), ("1.5MiB", 1_572_864)],
)
def test_byte_size_parses_supported_units(value: str, expected: int) -> None:
    assert _byte_size(value) == expected


@pytest.mark.parametrize("value", ["nope", "0", "-2MiB"])
def test_byte_size_rejects_invalid_values(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        _byte_size(value)


def test_cli_prints_json_and_applies_failure_threshold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("This sample mentions a keylogger.", encoding="utf-8")

    result = main([str(sample), "--format", "json", "--fail-on", "high"])

    assert result == EXIT_FINDINGS
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["highest_severity"] == "high"


def test_cli_writes_sarif_report(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    output = tmp_path / "nested" / "report.sarif"
    sample.write_text("ordinary text", encoding="utf-8")

    result = main([str(sample), "--format", "sarif", "--output", str(output)])

    assert result == EXIT_CLEAN
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_cli_reports_missing_target(capsys: pytest.CaptureFixture[str]) -> None:
    result = main(["definitely-does-not-exist"])

    assert result == EXIT_ERROR
    assert "target does not exist" in capsys.readouterr().err


def test_cli_reports_invalid_custom_rules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "target.txt"
    rules = tmp_path / "rules.json"
    target.write_text("content", encoding="utf-8")
    rules.write_text("{not-json", encoding="utf-8")

    result = main([str(target), "--rules", str(rules)])

    assert result == EXIT_ERROR
    assert "invalid JSON" in capsys.readouterr().err
