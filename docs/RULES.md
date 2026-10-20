# Rule Authoring

Rule packs are UTF-8 JSON objects with a name and a non-empty list of rules.

```json
{
  "name": "team-rules",
  "version": 1,
  "rules": [
    {
      "id": "execution.example",
      "name": "Example execution signal",
      "description": "Explains why this evidence matters.",
      "category": "execution",
      "severity": "high",
      "patterns": [
        "Exact literal",
        {
          "kind": "regex",
          "expression": "example[-_ ]command\\s+https?://",
          "case_sensitive": false
        }
      ]
    }
  ]
}
```

## Rule fields

| Field | Requirement |
| --- | --- |
| `id` | Unique, 3-64 characters, using lowercase letters, digits, `.`, `_`, or `-`. |
| `name` | Short analyst-facing title. |
| `description` | Explanation of the behavior or risk. |
| `category` | Stable behavior group such as `execution` or `persistence`. |
| `severity` | One of `info`, `low`, `medium`, `high`, or `critical`. |
| `patterns` | Non-empty list of literal strings or pattern objects. |

Pattern objects accept `kind` (`literal` or `regex`), `expression`, and an optional `case_sensitive` boolean. Plain strings are case-insensitive literals.

## Authoring guidance

- Detect a behavior or artifact with investigative value.
- Use literals when regular expressions are unnecessary.
- Keep regexes bounded and specific. Expressions are limited to 512 characters, but Python's regex engine has no per-match timeout.
- Avoid broad single words such as `password`, `payload`, or `shell`; they produce weak evidence in ordinary source code.
- Assign severity from the evidence itself, not the worst possible interpretation.
- Test true positives, near misses, mixed case, binary strings, and likely false-positive contexts.

## Validation

The pack is fully validated and every regex is compiled before scanning begins. Invalid JSON, duplicate IDs, unknown severities, unsupported pattern kinds, and malformed regexes return exit code `2`.

```bash
swa ./sample --rules ./rules/team-rules.json
```
