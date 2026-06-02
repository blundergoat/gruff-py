# Glossary - gruff-py

Last reviewed 2026-05-24.

This glossary defines terms used by `gruff-py`, its public reports, and local project memory. Keep shared gruff-family terms aligned with the sibling implementations; keep Python-specific differences explicit rather than making them look identical.

## Scope

`gruff-py` is the Python implementation of the gruff quality-scanner family. The Python package is `gruff-py`; the import package is `gruffpy`; the CLI binary is `gruff-py`; product code lives under `src/gruffpy/`.

## Shared Gruff Terms

### Analysis Report

The complete result of one scan: schema version, tool metadata, run metadata, paths, summary counts, score data, diagnostics, findings, baseline state, and optional diff/mutation state. Native JSON uses `gruff-py.analysis.v1`.

### Baseline

A reviewed-finding suppression file. `gruff-py` writes `gruff-py.baseline.v1` and can read legacy `gruff.baseline.v1`; entries match by stable finding identity so known findings can be suppressed without disabling rules.

### Changed-Code Scan

A scan filtered to changed lines or files. `--diff` filters current findings through local Git diff output; `--diff-vs=<base>` compares current findings against a base ref.

### Confidence

The certainty tier attached to a finding: `low`, `medium`, or `high`. It helps scoring and reviewers distinguish high-signal findings from heuristic prompts.

### Dashboard

The local browser UI served by `gruff-py dashboard`. It binds to 127.0.0.1:8765 by default and has no authentication; use `--port` when another gruff dashboard is already using the port.

### Diagnostic

A run-level problem such as an input error, parse error, config error, baseline error, diff error, or unexpected runtime condition. Fatal diagnostics force exit code `2`.

### Display Filter

A report-only filter such as `--min-severity`, include/exclude pillar, or include/exclude rule. Display filters change rendered output, not rule execution.

### Exit Codes

`0` means the run completed and no finding met the failure threshold. `1` means at least one finding met the threshold. `2` means a fatal diagnostic or invalid input stopped the requested scan from being fully trustworthy.

### Finding

One rule-produced result with rule ID, message, severity, confidence, pillar, location, remediation, metadata, and fingerprint.

### Fingerprint

A stable 16-character SHA-256-derived identifier. It is intended to match `gruff-php` byte-for-byte for equivalent finding identity fields.

### Gruff Config

Project configuration that tunes discovery, allowlists, rule selection, and per-rule thresholds/severity/options. Shared keys are `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection`, and `rules.<id>`.

### Hotspot Output

A compact JSON view of the worst file offenders for dashboards or trend tooling. `gruff-py` emits it as `gruff-py.hotspot.v1`.

### Output Format

A renderer over the same analysis report. `analyse` supports `text`, `json`, `html`, `markdown`, `github`, `hotspot`, and `sarif`; `report` supports `html` and `json`.

### Pillar

The quality dimension a finding belongs to, such as `complexity`, `security`, `sensitive-data`, or `test-quality`. Pillars feed per-pillar scoring and display filters.

### Rule Catalogue

The set of built-in rules plus their public metadata. `list-rules --format json` is the source of truth for rule IDs, pillars, severity, confidence, thresholds, options, and default enablement.

### Rule ID

Stable public identifier for one rule, using dotted gruff-family names such as `size.file-length`, `docs.missing-function-docstring`, and `sensitive-data.high-entropy-string`. Documentation rules use `docs.*` while the emitted pillar is `documentation`.

### SARIF

Static Analysis Results Interchange Format. `gruff-py` emits SARIF 2.1.0 from the same report data used by the other renderers.

### Score And Grade

The numeric and letter quality summary derived from findings after baseline and filter layers have been applied according to the current command.

### Secret Preview

A redacted representation of sensitive-data matches. Raw secret values must not appear in terminal, JSON, SARIF, GitHub, Markdown, hotspot, or HTML output.

### Severity And Failure Threshold

`gruff-py` uses `advisory`, `warning`, and `error`. `--fail-on` controls exit code `1`; `none` reports findings without failing for severity.

### Source Discovery

The process that turns input paths into classifiable Python or text files. `paths.ignore` always applies; `--include-ignored` opts into default-ignored and Git-ignored paths for deliberate inspection.

### Trust Boundary

Default scans are local source inspections. `gruff-py` parses files and may call Git for explicit diff scans; it does not run target application code, run tests, query vulnerability feeds, or contact package registries. Explicit mutation options may run external tooling.

## Implementation-Specific Terms

### Typed Package

The import package `gruffpy` ships a `py.typed` marker so type checkers can consume its annotations.

### Python AST Unit

An analysis unit for one discovered file. Python units can carry an AST; text units carry source text only and are handled by text-capable rules.

### Pyproject Config

Config discovery prefers explicit `--config`, then `.gruff-py.yaml`, then legacy `.gruff.yaml`, then `[tool.gruff-py]` or legacy `[tool.gruff]` in `pyproject.toml`.

### Source Text Rule

A rule that can run on non-Python text/config files as well as Python files. Sensitive-data checks use this path.

### Reserved Pillar

A schema or future-catalogue pillar with no shipping rules in the current release, such as `modernisation`, `coupling`, `architecture`, or `mutation`.

### Mutation Compatibility

The CLI exposes mutation-related options for compatibility with gruff workflows. Mutation findings depend on explicit external report/run options, not default scans.

### PHP-Compatible Fingerprint

The Python fingerprint algorithm is constrained by the PHP implementation for shared finding identity fields. Compatibility is about identity bytes, not identical schemas.

## Agent Workflow Terms

### GOAT Flow

Local agent workflow framework installed from `@blundergoat/goat-flow`. It provides skills, audit commands, safety references, and `.goat-flow/` project-memory directories.

### Agent-Owned Surface

Files one agent setup owns without widening scope. Claude owns `CLAUDE.md` and `.claude/**`; Codex owns `AGENTS.md` and `.codex/**`; shared agent skills live under `.agents/skills/**`.

### Learning Loop

Durable shared project-memory directories under `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/`.
