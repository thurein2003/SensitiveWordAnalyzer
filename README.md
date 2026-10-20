# Sensitive Word Analyzer

[![CI](https://github.com/thurein2003/SensitiveWordAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/thurein2003/SensitiveWordAnalyzer/actions/workflows/ci.yml)
[![CodeQL](https://github.com/thurein2003/SensitiveWordAnalyzer/actions/workflows/codeql.yml/badge.svg)](https://github.com/thurein2003/SensitiveWordAnalyzer/actions/workflows/codeql.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776ab.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)

Sensitive Word Analyzer (`swa`) is a defensive, read-only static triage tool for suspicious files and directory trees. It combines contextual rules, string extraction, file hashes, entropy measurement, file signatures, and indicator-of-compromise (IOC) extraction in one dependency-free Python engine.

It is designed for analyst triage and CI checks. It does not execute, import, emulate, decrypt, or modify the files it scans.

## Why this project exists

Simple keyword scripts are useful teaching tools, but they break down on binary files, large directory trees, automation pipelines, and untrusted input. `swa` adds bounded reads, validated rule packs, symlink controls, machine-readable output, and tested failure semantics while keeping the workflow straightforward.

## Features

- Recursively scans text and binary files without executing them.
- Extracts printable ASCII, UTF-16 LE, and UTF-16 BE strings from binaries.
- Applies validated literal and regular-expression rules with severity and category metadata.
- Ships with rules for credential access, execution, persistence, evasion, command and control, collection, and impact signals.
- Calculates MD5, SHA-1, SHA-256, Shannon entropy, and lightweight file signatures.
- Extracts URLs, IPv4 addresses, email addresses, and likely domains.
- Produces terminal text, deterministic JSON, and SARIF 2.1.0 reports.
- Supports severity filtering and CI failure thresholds.
- Uses bounded file reads, finding caps, hidden-file controls, and cycle-safe symlink traversal.
- Caps file and directory discovery and reports incomplete scans as operational errors.
- Runs on Python 3.9+ with no runtime dependencies.

## Quick start

Install from GitHub with `pipx`:

```bash
pipx install git+https://github.com/thurein2003/SensitiveWordAnalyzer.git
swa ./samples
```

Or use a virtual environment from a clone:

```bash
git clone https://github.com/thurein2003/SensitiveWordAnalyzer.git
cd SensitiveWordAnalyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
swa ./path/to/file-or-directory
```

No installation is required for a source checkout:

```bash
PYTHONPATH=src python -m sensitive_word_analyzer ./path/to/target
```

## Common workflows

Scan a directory and show high or critical findings:

```bash
swa ./quarantine --min-severity high
```

Write a JSON report and fail when a high-severity signal is present:

```bash
swa ./quarantine --format json --output reports/scan.json --fail-on high
```

Create SARIF for GitHub code scanning or another compatible platform:

```bash
swa ./quarantine --format sarif --output reports/scan.sarif
```

Use a custom rule pack and a lower file-size ceiling:

```bash
swa ./incoming --rules rules/team-rules.json --max-file-size 2MiB
```

Run in a container with the target mounted read-only:

```bash
docker build -t sensitive-word-analyzer .
docker run --rm -v "$PWD/samples:/scan:ro" sensitive-word-analyzer /scan
```

## CLI reference

| Option | Purpose |
| --- | --- |
| `--rules PATH` | Load a custom JSON rule pack. |
| `--format text\|json\|sarif` | Select the output format. |
| `-o, --output PATH` | Write the report to a file. |
| `--no-recursive` | Scan only direct children of a directory. |
| `--include-hidden` | Include dotfiles and hidden directories. |
| `--follow-symlinks` | Follow links with directory-cycle detection. |
| `--max-file-size SIZE` | Limit bytes read from each file; default is `10MiB`. |
| `--max-findings N` | Cap retained findings per file; default is `200`. |
| `--max-files N` | Cap files discovered in one scan; default is `10000`. |
| `--max-directories N` | Cap directories traversed in one scan; default is `10000`. |
| `--workers N` | Set concurrent file scanners; default is `4`. |
| `--min-severity LEVEL` | Hide findings below the selected severity. |
| `--fail-on LEVEL` | Return exit code 1 at or above the selected severity. |

Exit codes are stable: `0` means the scan completed without reaching the failure threshold, `1` means the threshold was reached, and `2` means a configuration or scanning error occurred.

Custom rule packs are operator-controlled configuration. Review third-party regex rules before use; Python's regex engine has no per-match timeout.

## Rules and results

Rules are detection signals, not verdicts. A match should be investigated alongside file origin, execution context, signer reputation, sandbox results, and other telemetry. The default rules intentionally favor explainable evidence over opaque scoring.

See [Rule authoring](docs/RULES.md) for the JSON schema and [Architecture](docs/ARCHITECTURE.md) for the analysis pipeline. The [Security model](docs/SECURITY_MODEL.md) documents trust boundaries, resource limits, and known limitations.

## Development

```bash
python -m pip install -e '.[dev]'
make check
```

The repository enforces Ruff formatting and linting, strict mypy checks, more than 50 focused tests, and at least 90% branch coverage. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Responsible use

Use this project only on files and systems you own or are authorized to analyze. Do not treat a match as proof that a file is malicious, and do not submit confidential samples to public issues.

Security concerns about this project should follow [SECURITY.md](SECURITY.md).
