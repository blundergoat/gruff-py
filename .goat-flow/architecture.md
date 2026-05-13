# Architecture

## System Overview

gruff-py is a Click-based Python CLI that analyses project files and emits text or JSON quality reports. `src/gruff/cli.py` orchestrates config loading, source discovery, parsing, rule execution, scoring, reporting, and exit-code selection; domain objects live in focused packages under `src/gruff/`.

The main runtime components are `ConfigLoader`, `SourceDiscovery`, `PythonFileParser`, `RuleRegistry`, `CompositeFindingFactory`, `ScoreCalculator`, `TextReporter`, and `JsonReporter`. Rules are isolated behind the `Rule` interface so the catalogue grows without making CLI parsing or report rendering own rule-specific behaviour.

## Request Flow

Representative command path: `gruff analyse src/ --format json` enters `src/gruff/cli.py`, builds default rule settings from `RuleRegistry.defaults()`, loads project config via `ConfigLoader` (precedence: `--config <path>`, then `.gruff.yaml` in the project root, then `[tool.gruff]` in `pyproject.toml`), discovers Python and text files with `SourceDiscovery`, parses Python files with `PythonFileParser`, runs enabled rules through `RuleRegistry.analyse()`, calculates a score with `ScoreCalculator`, renders the `AnalysisReport` with `JsonReporter`, and exits with `0`, `1`, or `2` based on diagnostics and `--fail-on`.

Unknown keys in `[tool.gruff]` or `.gruff.yaml` reject strictly with a `config-error` diagnostic. Parse or config diagnostics are part of the report and force exit code `2`. Findings at or above the selected `FailThreshold` force exit code `1`; clean runs exit `0`.

## Auth / Trust Boundaries

There is no authentication layer, service account, network request, or long-running server. Trust boundaries are local filesystem inputs: user-supplied paths, `--config`, `pyproject.toml`, and source files read by the CLI.

`.claude/settings.json` and `.claude/hooks/deny-dangerous.sh` protect Claude Code from secret reads/writes and dangerous shell operations during agent sessions. Application runtime does not enforce those agent guardrails.

## Data Flow

Durable project configuration lives in `pyproject.toml`; package resolution is locked by `uv.lock`. Runtime analysis state is in memory: discovered `SourceFile` objects become `AnalysisUnit` objects, rules produce `Finding` objects, and `AnalysisReport.to_dict()` provides the JSON schema payload.

The compatibility contracts are explicit in `src/gruff/analysis/schema.py` and `src/gruff/finding/fingerprint.py`. Fingerprints intentionally reproduce gruff-php byte behaviour, including PHP-style slash escaping before hashing.

## Rules And Scoring

`RuleRegistry.defaults()` instantiates the full rule catalogue: 97 rules across 9 active pillars (`size`, `complexity` + `maintainability`, `dead-code` + `waste`, `naming`, `documentation`, `security`, `sensitive-data`, `test-quality`). Each pillar lives under `src/gruff/rule/<pillar>/`. A subset of `test-quality` rules ship default-off and are opted in via `[tool.gruff.rules]`. The `design` pillar carries no per-unit rules — `CompositeFindingFactory` synthesises `design.god-method` findings post-pass when size + complexity overlap on a symbol. `modernisation` is declared in the score model but its rule catalogue is still being built. `AnalysisConfig.from_registry()` snapshots each rule's default settings; selection and per-rule overrides are applied by `ConfigLoader`.

Rules subclassing `SourceTextRule` additionally run on `.env`/`.toml`/`.yaml`/`.json`/`.ini`/`.conf` text files — the secret/PHI scanners under `sensitive-data.*` use this seam. Several test-quality rules read `pyproject.toml` once per run via `_pytest_config`; scope detection for test-quality rules is memoised through `_test_quality_node_helper` so the catalogue computes per-unit scope exactly once.

`ScoreCalculator` scores the declared pillars plus any pillar found in findings, using the two-axis severity × confidence weight model (severity weights 12/4/1, confidence 1.0/0.75/0.5, pillar multiplier ×4, file multiplier ×5). Grades land at 90/80/70/60 for A/B/C/D, anything below is F. The output is a composite grade, per-pillar grades, and top-offender file grades.

## Reporting And Schemas

`JsonReporter` serializes `AnalysisReport.to_dict()` with four-space indentation, slashes escaped, and non-ASCII escaped — byte-equivalent to the PHP reference's `JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES`-default behaviour. `TextReporter` renders the same report as a console summary.

`OutputFormat` lists future formats (HTML, Markdown, GitHub annotations, SARIF, hotspot), but only `text` and `json` ship in 0.1.0-dev; other choices currently render through `TextReporter`. The `gruff.hotspot.v1` schema is declared in `src/gruff/analysis/schema.py` for cross-impl stability but its reporter has not yet shipped.

## Deployment / Operations

Local development uses `uv` through the `Makefile`. CI in `.github/workflows/ci.yml` runs on Python 3.11 and 3.12 with `ruff check`, `ruff format --check`, `mypy`, and `pytest`.

Packaging uses Hatchling from `pyproject.toml`; `uv build` emits artifacts under `dist/`. Pre-commit config mirrors the same checks, but its ruff hook auto-fixes, so non-mutating verification should use the explicit CI commands.
