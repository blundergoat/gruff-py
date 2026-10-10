# gruff-py docs

Use these docs with the top-level README for the stable user-facing surface.

## Mission

gruff-py governs AI-generated code so a human reviewer can verify, trust, and sign off on it: legible enough to verify, secure where the eye fails, and tested for real rather than padded with low-signal ceremony. See [Mission](mission.md) for the full statement and decision records.

## Core Docs

- [Mission](mission.md) - why gruff-py exists: govern AI-generated code for human sign-off.
- [Configuration](configuration.md) - config discovery, schema, allowlists, and rule overrides.
- [Rules](rules.md) - generated rule IDs, severities, thresholds, and remediation guidance.
- [Output Formats](output-formats.md) - text, JSON, HTML, Markdown, GitHub annotations, hotspot, and SARIF.
- [Coding-Agent Hook](agent-hook.md) - changed-region commands for local agent governance.
- [CI Integration](ci-integration.md) - GitHub Actions, SARIF upload, baselines, and diff flags.
- [Dashboard](dashboard.md) - local dashboard flags, controls, and safety notes.
- [Upgrading](../UPGRADING.md) - what each release line breaks, and how to go back.
- [Releasing](releasing.md) - maintainer-only: release checks and packaging notes.

## Task Docs

- [Triage](triage.md) - read a noisy run with `summary --group-by=rule` instead of scrolling findings.
- [Explain](explain.md) - inspect one rule's defaults, options, escape hatches, and related rules.
- [Reporting](reporting.md) - stable link target that routes to the pages above.

## Shared Contract

Cross-language naming and CLI expectations live in `FAMILY-CONTRACT.md` at the
gruff workspace root (sibling to this package). That file is workspace-internal
and ships in no published artifact; the behaviour it governs is documented here
and in the top-level README. Python keeps the hidden `metric-calibration`
command for rule tuning.
