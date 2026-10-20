from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict

import pytest

from sensitive_word_analyzer.models import Severity
from sensitive_word_analyzer.scanner import Scanner, ScanOptions


def test_text_scan_finds_rules_hashes_and_indicators(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    content = b"keylogger callback-server 192.0.2.10 https://evil.example/path\n"
    sample.write_bytes(content)

    report = Scanner().scan(sample)
    file = report.files[0]

    assert file.hashes["sha256"] == hashlib.sha256(content).hexdigest()
    assert file.entropy and file.entropy > 0
    assert {finding.rule_id for finding in file.findings} >= {
        "collection.keylogging",
        "command-control.beacon",
    }
    assert file.indicators["ipv4"] == ["192.0.2.10"]
    assert file.indicators["urls"] == ["https://evil.example/path"]


def test_binary_scan_extracts_ascii_and_utf16_strings(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(
        b"MZ\x00\x01keylogger\x00" + "IsDebuggerPresent".encode("utf-16-le") + b"\x00"
    )

    file = Scanner().scan(sample).files[0]

    assert file.file_type == "pe-executable"
    assert {finding.source for finding in file.findings} >= {
        "ascii-strings",
        "utf16le-strings",
    }


def test_binary_scan_extracts_big_endian_utf16_strings(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00\x01" + "keylogger".encode("utf-16-be") + b"\x00")

    findings = Scanner().scan(sample).files[0].findings

    assert any(finding.source == "utf16be-strings" for finding in findings)


def test_directory_options_control_recursion_and_hidden_files(tmp_path: Path) -> None:
    (tmp_path / "visible.txt").write_text("keylogger", encoding="utf-8")
    (tmp_path / ".hidden.txt").write_text("keylogger", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "child.txt").write_text("keylogger", encoding="utf-8")

    shallow = Scanner(options=ScanOptions(recursive=False)).scan(tmp_path)
    deep = Scanner(options=ScanOptions(include_hidden=True)).scan(tmp_path)

    assert len(shallow.files) == 1
    assert len(deep.files) == 3


def test_large_file_is_skipped(tmp_path: Path) -> None:
    sample = tmp_path / "large.txt"
    sample.write_text("too much text", encoding="utf-8")

    file = Scanner(options=ScanOptions(max_file_size=3)).scan(sample).files[0]

    assert file.skipped_reason and "size limit" in file.skipped_reason
    assert file.hashes == {}


def test_minimum_severity_and_finding_cap_are_enforced(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("keylogger keylogger keylogger CreateProcessA", encoding="utf-8")
    options = ScanOptions(minimum_severity=Severity.HIGH, max_findings_per_file=2)

    findings = Scanner(options=options).scan(sample).files[0].findings

    assert len(findings) == 2
    assert all(finding.severity.rank >= Severity.HIGH.rank for finding in findings)


def test_empty_file_has_zero_entropy(tmp_path: Path) -> None:
    sample = tmp_path / "empty"
    sample.touch()
    file = Scanner().scan(sample).files[0]
    assert file.entropy == 0.0
    assert file.file_type == "text"


def test_invalid_ipv4_candidate_is_not_reported(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("999.999.999.999", encoding="utf-8")
    assert Scanner().scan(sample).files[0].indicators == {}


def test_domains_require_context_or_likely_public_suffix(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text(
        "example.suspicious AnalyzedFile.txt user@corp.internal "
        "https://control.unusual/path public.example.com",
        encoding="utf-8",
    )

    domains = Scanner().scan(sample).files[0].indicators["domains"]

    assert domains == ["control.unusual", "corp.internal", "public.example.com"]


def test_malformed_url_does_not_abort_scan(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("http://[invalid", encoding="utf-8")

    file = Scanner().scan(sample).files[0]

    assert file.error is None
    assert file.indicators["urls"] == ["http://[invalid"]


def test_symlink_is_skipped_by_default(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    link = tmp_path / "link.txt"
    target.write_text("keylogger", encoding="utf-8")
    link.symlink_to(target)

    file = Scanner().scan(link).files[0]

    assert file.file_type == "symlink"
    assert file.skipped_reason == "symbolic links are disabled"


def test_symlink_can_be_followed(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    link = tmp_path / "link.txt"
    target.write_text("keylogger", encoding="utf-8")
    link.symlink_to(target)

    file = Scanner(options=ScanOptions(follow_symlinks=True)).scan(link).files[0]

    assert file.skipped_reason is None
    assert file.findings


@pytest.mark.parametrize(
    "options",
    [
        {"max_file_size": 0},
        {"max_findings_per_file": 0},
        {"max_strings_bytes": 0},
        {"max_files": 0},
        {"max_directories": 0},
        {"workers": 0},
    ],
)
def test_scan_options_reject_non_positive_limits(options: Dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        ScanOptions(**options)


def test_file_discovery_limit_marks_report_incomplete(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"{index}.txt").write_text("content", encoding="utf-8")

    report = Scanner(options=ScanOptions(max_files=2)).scan(tmp_path)

    assert len(report.files) == 2
    assert report.warnings == ["file discovery stopped at the 2-file limit"]


def test_directory_discovery_limit_marks_report_incomplete(tmp_path: Path) -> None:
    child = tmp_path / "child"
    child.mkdir()
    (child / "sample.txt").write_text("content", encoding="utf-8")

    report = Scanner(options=ScanOptions(max_directories=1)).scan(tmp_path)

    assert report.files == []
    assert report.warnings == ["directory discovery stopped at the 1-directory limit"]
