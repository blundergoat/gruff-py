# Reporting

This page is a stable link target. The reporting reference moved to pages split
by task; each section below names where its content now lives.

| Topic | Page |
|---|---|
| Every `--format` value, and what each is for | [Output Formats](output-formats.md) |
| JSON shape, finding identity, schema strings | [Output Formats → JSON](output-formats.md#json) |
| SARIF renderer contract and validation | [Output Formats → SARIF](output-formats.md#sarif) |
| Display filters (`--min-severity`, `--include-pillar`, `--exclude-rule`) | [Output Formats → Display Filters](output-formats.md#display-filters) |
| Changed-region scoping and `suppressedCount` | [Output Formats → Changed-Region Scoping](output-formats.md#changed-region-scoping-native-diff-mode) |
| GitHub Actions workflow, SARIF upload, baselines | [CI Integration](ci-integration.md) |
| `--fail-on`, `minimumSeverity:`, and exit codes | [Configuration → Severity Gate](configuration.md#severity-gate) |
| Reading a noisy run | [Triage](triage.md) |

## JSON

JSON reports use schema string `gruff.analysis.v2`. The top-level shape, the
`fingerprint` and `stableIdentity` input sets, and the changed-region additions
are documented in [Output Formats → JSON](output-formats.md#json).

## Exit Codes

Codes `0`, `1`, and `2`, and the per-command `--fail-on` defaults, are in
[Output Formats → Exit Codes](output-formats.md#exit-codes).
