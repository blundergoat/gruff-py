# gruff-py docs

Use these docs with the top-level README for the stable user-facing surface.

## Core Docs

- [Configuration](configuration.md) - config discovery, schema, allowlists, and rule overrides.
- [Rules](rules.md) - generated rule IDs, severities, thresholds, and remediation guidance.
- [Output Formats](output-formats.md) - text, JSON, HTML, Markdown, GitHub annotations, hotspot, and SARIF.
- [CI Integration](ci-integration.md) - GitHub Actions, SARIF upload, baselines, and diff flags.
- [Dashboard](dashboard.md) - local dashboard flags, controls, and safety notes.
- [Releasing](releasing.md) - release checks and packaging notes.

## Extra Docs

- [Reporting](reporting.md) - combined reporting and CI details retained for existing links.

## Shared Contract

Cross-language naming and CLI expectations live in `CONTRACT.md` at the
gruff workspace root (sibling to this package). Python keeps the hidden
`metric-calibration` command for rule tuning.
