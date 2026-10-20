# Security Model

## Goal

Sensitive Word Analyzer inspects potentially untrusted files while minimizing side effects and resource use. It is a static triage tool, not an isolation boundary.

## Security properties

- Target content is read as bytes and is never executed, imported, evaluated, or written back.
- File reads are rejected above the configured size limit and checked again after reading.
- Files are opened through descriptors, regular-file status is verified, reads are bounded to `limit + 1` bytes, and supported platforms enforce no-follow semantics at open time.
- Binary string extraction is bounded independently from the file-size limit.
- Findings retained per file are capped.
- File and directory discovery are capped; hitting either cap marks the scan incomplete and returns operational exit code `2`.
- Hidden paths and symbolic links are excluded by default.
- Opt-in symlink traversal tracks device and inode identities to prevent directory cycles.
- `.git` directories are always excluded to avoid scanning repository internals and object databases.
- Rule packs are parsed as JSON and validated before target discovery.
- Terminal output escapes control characters from untrusted evidence.
- Report files are written only to an explicit user-provided path.

## Trust boundaries

Targets are untrusted. Custom rule packs, CLI arguments, and the selected output directory are operator-controlled configuration. The local Python interpreter, operating system, and installed package are trusted.

## Known limitations

- Python's built-in regex engine does not provide a per-match timeout. Review third-party custom rules before use; a hostile configured regex can consume excessive CPU even though input size is bounded.
- A file can change between metadata inspection and reading. The scanner detects growth beyond the limit but does not provide filesystem snapshot semantics.
- Archive contents are not unpacked. Only visible strings in the archive container are considered.
- File signatures are intentionally lightweight and are not a replacement for a full parser or `libmagic`.
- IOC extraction is syntactic and can include benign infrastructure or miss encoded indicators.
- Hashes identify bytes; MD5 and SHA-1 are included for ecosystem lookup compatibility, not cryptographic trust.
- Following symlinks can move analysis outside the original target tree. Enable it only when that behavior is intended.

## Safe operating guidance

Analyze unknown files on an isolated workstation or sandbox, mount sample collections read-only, keep executable permissions disabled, and use least-privilege accounts. Do not rely on this tool alone to contain or classify malware.
