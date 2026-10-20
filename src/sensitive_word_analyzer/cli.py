"""Command-line interface for Sensitive Word Analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .models import Severity
from .reporters import render_report
from .rules import RuleSet, RuleValidationError
from .scanner import Scanner, ScanOptions

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _byte_size(value: str) -> int:
    units = {
        "b": 1,
        "kb": 1_000,
        "kib": 1_024,
        "mb": 1_000_000,
        "mib": 1_048_576,
        "gb": 1_000_000_000,
        "gib": 1_073_741_824,
    }
    normalized = value.strip().lower()
    for suffix in sorted(units, key=len, reverse=True):
        if normalized.endswith(suffix):
            number = normalized[: -len(suffix)].strip()
            break
    else:
        suffix = "b"
        number = normalized

    try:
        result = int(float(number) * units[suffix])
    except (ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(f"invalid byte size: {value!r}") from exc
    if result < 1:
        raise argparse.ArgumentTypeError("byte size must be positive")
    return result


def _positive_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if result < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="swa",
        description="Perform read-only, rule-driven static triage on files and directories.",
    )
    parser.add_argument("target", type=Path, help="file or directory to scan")
    parser.add_argument("--rules", type=Path, help="custom JSON rule pack")
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument("-o", "--output", type=Path, help="write the report to this file")
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="scan only files directly inside the target directory",
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="include hidden files and directories",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="follow symbolic links while preventing directory cycles",
    )
    parser.add_argument(
        "--max-file-size",
        type=_byte_size,
        default=10 * 1024 * 1024,
        metavar="SIZE",
        help="largest file to read, such as 500KiB or 20MiB (default: 10MiB)",
    )
    parser.add_argument(
        "--max-findings",
        type=_positive_int,
        default=200,
        metavar="N",
        help="maximum findings retained per file (default: 200)",
    )
    parser.add_argument(
        "--max-files",
        type=_positive_int,
        default=10_000,
        metavar="N",
        help="maximum files discovered in one scan (default: 10000)",
    )
    parser.add_argument(
        "--max-directories",
        type=_positive_int,
        default=10_000,
        metavar="N",
        help="maximum directories traversed in one scan (default: 10000)",
    )
    parser.add_argument(
        "--workers",
        type=_positive_int,
        default=4,
        metavar="N",
        help="number of concurrent file scanners (default: 4)",
    )
    parser.add_argument(
        "--min-severity",
        choices=tuple(severity.value for severity in Severity),
        default=Severity.INFO.value,
        help="lowest severity included in the report (default: info)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("never",) + tuple(severity.value for severity in Severity),
        default="never",
        help="return exit code 1 when this severity or higher is found",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _write_report(content: str, output: Optional[Path]) -> None:
    if output is None:
        print(content)
        return
    output = output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content + ("" if content.endswith("\n") else "\n"), encoding="utf-8")


def _threshold_reached(report_severity: Optional[Severity], threshold: str) -> bool:
    if threshold == "never" or report_severity is None:
        return False
    return report_severity.rank >= Severity.parse(threshold).rank


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        rules = RuleSet.from_file(args.rules) if args.rules else RuleSet.default()
        options = ScanOptions(
            recursive=not args.no_recursive,
            include_hidden=args.include_hidden,
            follow_symlinks=args.follow_symlinks,
            max_file_size=args.max_file_size,
            max_findings_per_file=args.max_findings,
            max_files=args.max_files,
            max_directories=args.max_directories,
            workers=args.workers,
            minimum_severity=Severity.parse(args.min_severity),
        )
        report = Scanner(rules=rules, options=options).scan(args.target)
        _write_report(render_report(report, args.format, rules), args.output)
    except (FileNotFoundError, OSError, RuleValidationError, ValueError) as exc:
        print(f"swa: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if report.error_count or report.warnings:
        return EXIT_ERROR
    if _threshold_reached(report.highest_severity, args.fail_on):
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
