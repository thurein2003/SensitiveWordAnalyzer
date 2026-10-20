# Architecture

Sensitive Word Analyzer is a dependency-free Python package with a thin CLI over a reusable analysis engine.

```text
CLI arguments
    |
    v
Rule validation -----> Scan options and resource limits
    |                         |
    +------------+------------+
                 v
         Safe target discovery
                 |
                 v
      Bounded concurrent file reads
                 |
        +--------+---------+
        |                  |
        v                  v
 hashes / entropy    text / string extraction
                           |
                    +------+------+
                    |             |
                    v             v
                rule matches   IOC extraction
                    |             |
                    +------+------+
                           v
                    typed scan report
                           |
                  +--------+--------+
                  |        |        |
                 text     JSON    SARIF
```

## Modules

- `models.py` defines severity, finding, file, and aggregate report contracts.
- `rules.py` validates JSON rule packs and compiles literal and regex patterns once.
- `scanner.py` discovers targets, enforces limits, reads bytes, extracts evidence, and applies rules.
- `reporters.py` renders one report model into terminal text, JSON, or SARIF 2.1.0.
- `cli.py` maps command-line arguments to engine options and stable exit codes.

## Design decisions

### No runtime dependencies

The standard library is sufficient for bounded file traversal, hashing, string extraction, JSON, concurrency, and reporting. This keeps deployment and supply-chain exposure small.

### Evidence instead of a malware verdict

The engine returns named findings with severity, category, matched text, a bounded snippet, and source location when available. It does not combine signals into an unexplained malicious/clean score.

### Immutable configuration during a scan

Rules and scan options are validated before target discovery. Worker threads receive the same immutable configuration, and results are returned in deterministic path order.

### Bounded analysis

File size, extracted binary bytes, and retained findings are capped. Symlink traversal is opt-in and directory identities are tracked to prevent cycles.

## Extension points

New rule packs require no code changes. New report formats should consume `ScanReport` rather than re-reading files. Deeper parsers can be added behind the scanner while preserving the existing typed result contract.
