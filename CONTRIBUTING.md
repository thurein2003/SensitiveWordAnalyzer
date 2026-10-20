# Contributing

Contributions that improve detection quality, safety, portability, documentation, and test coverage are welcome.

## Set up the project

```bash
git clone https://github.com/thurein2003/SensitiveWordAnalyzer.git
cd SensitiveWordAnalyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pre-commit install
```

## Before opening a pull request

Run the same checks used by CI:

```bash
make check
```

Keep changes focused, add tests for behavioral changes, and update user documentation when a CLI or rule contract changes. Use harmless synthetic fixtures; never commit live malware, credentials, private data, or copyrighted samples.

## Rule contributions

New rules should describe a behavior, not merely name a tool or malware family. Prefer bounded, explainable expressions and include positive and negative tests. See [docs/RULES.md](docs/RULES.md).

## Commit and pull request guidance

- Use an imperative, descriptive commit subject.
- Explain the user-visible effect and security assumptions.
- Link related issues.
- Confirm tests, lint, typing, and coverage pass.
- Note false-positive and performance tradeoffs for detection changes.

By contributing, you agree that your work is licensed under the MIT License.
