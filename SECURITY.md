# Security Policy

## Supported versions

Security fixes are applied to the latest release on the `main` branch.

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or attach a sensitive sample to an issue.

Use GitHub's private vulnerability reporting flow:

https://github.com/thurein2003/SensitiveWordAnalyzer/security/advisories/new

Include the affected version, operating system, reproduction steps, impact, and any suggested remediation. Remove secrets and confidential sample content. Acknowledgement is targeted within 72 hours, followed by a status update within seven days.

## Scope

Reports about unsafe file handling, path traversal, terminal escape injection, rule-pack denial of service, dependency compromise, and incorrect security boundaries are in scope. Detection misses and false positives are normally product-quality issues unless they violate a documented security guarantee.

The scanner is a triage aid, not an antivirus engine or sandbox. Its guarantees and limitations are documented in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
