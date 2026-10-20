# Sensitive Word Analyzer

[![CI](https://github.com/thurein2003/SensitiveWordAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/thurein2003/SensitiveWordAnalyzer/actions/workflows/ci.yml)
[![CodeQL](https://github.com/thurein2003/SensitiveWordAnalyzer/actions/workflows/codeql.yml/badge.svg)](https://github.com/thurein2003/SensitiveWordAnalyzer/actions/workflows/codeql.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776ab.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)

`swa` is a read-only static triage tool for suspicious files. It never executes or changes scanned files.

- Scans text and binary files with configurable rules.
- Reports hashes, entropy, file signatures, and extracted IOCs.
- Outputs readable text, JSON, or SARIF.
- Uses bounded reads and discovery to limit resource use.
- Runs on Python 3.9+ with no runtime dependencies.

## Install

```bash
pipx install git+https://github.com/thurein2003/SensitiveWordAnalyzer.git
swa ./path/to/file-or-directory --min-severity high
```

## Demo

From a source checkout, run this harmless example:

```bash
PYTHONPATH=src python3 -m sensitive_word_analyzer \
  examples/demo-sample.txt \
  --rules examples/custom_rules.json \
  --min-severity medium
```

![Real terminal recording of a scan using the synthetic example](docs/assets/swa-demo.gif)

The sample uses `example.invalid`; findings are signals for investigation, not verdicts.

## How it works

```mermaid
flowchart LR
    A[File or directory] --> B[Bounded discovery]
    B --> C[Read-only analysis]
    C --> D[Strings, hashes, entropy, signatures]
    C --> E[Rule matches and IOC extraction]
    D --> F[Text, JSON, or SARIF]
    E --> F
```

## References

[Architecture](docs/ARCHITECTURE.md) · [Rule authoring](docs/RULES.md) · [Security model](docs/SECURITY_MODEL.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

Run `swa --help` for all options. Use the tool only on files you are authorized to analyze.
