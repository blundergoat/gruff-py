# Architecture

## System Overview

gruff-py is a Click-based Python CLI that analyses project files and emits text or JSON quality reports. The current implementation is intentionally small: `src/gruff/cli.py` orchestrates config loading, source discovery, parsing, rule execution, scoring, reporting, and exit-code selection while domain objects live in focused packages under `src/gruff/`.

The main runtime components are `ConfigLoader`, `SourceDiscovery`, `PythonFileParser`, `RuleRegistry`, `ScoreCalculator`, `TextReporter`, and `JsonReporter`. Rules are isolated behind the `Rule` interface so the catalogue can grow without making CLI parsing or report rendering own rule-specific behaviour.

## Request Flow

Representative command path: `gruff analyse src/ --format json` enters `src/gruff/cli.py`, builds default rule settings from `RuleRegistry.defaults()`, reads `[tool.gruff]` from `pyproject.toml` via `ConfigLoader`, discovers Python and text files with `SourceDiscovery`, parses Python files with `PythonFileParser`, runs enabled rules through `RuleRegistry.analyse()`, calculates a score with `ScoreCalculator`, renders the `AnalysisReport` with `JsonReporter`, and exits with `0`, `1`, or `2` based on diagnostics and `--fail-on`.

Parse or config diagnostics are part of the report and force exit code `2`. Findings at or above the selected `FailThreshold` force exit code `1`; clean runs exit `0`.

## Auth / Trust Boundaries

There is no authentication layer, service account, network request, or long-running server. Trust boundaries are local filesystem inputs: user-supplied paths, `--config`, `pyproject.toml`, and source files read by the CLI.

`.claude/settings.json` and `.claude/hooks/deny-dangerous.sh` protect Claude Code from secret reads/writes and dangerous shell operations during agent sessions. Application runtime does not enforce those agent guardrails.

## Data Flow

Durable project configuration lives in `pyproject.toml`; package resolution is locked by `uv.lock`. Runtime analysis state is in memory: discovered `SourceFile` objects become `AnalysisUnit` objects, rules produce `Finding` objects, and `AnalysisReport.to_dict()` provides the JSON schema payload.

The compatibility contracts are explicit in `src/gruff/analysis/schema.py` and `src/gruff/finding/fingerprint.py`. Fingerprints intentionally reproduce gruff-php byte behaviour, including PHP-style slash escaping before hashing.

## Rules And Scoring

`RuleRegistry.defaults()` currently registers `FileLengthRule` from `src/gruff/rule/size/file_length_rule.py`. `AnalysisConfig.from_registry()` snapshots each rule's default settings; selection and per-rule overrides are applied by `ConfigLoader`.

`ScoreCalculator` scores a static set of pillars plus any pillar found in findings. Penalties are weighted by severity and confidence, then reported as composite, per-pillar, and top-offender file grades.

## Reporting And Schemas

`JsonReporter` serializes `AnalysisReport.to_dict()` with four-space indentation and no extra transport wrapper. `TextReporter` renders the same report as a console summary.

`OutputFormat` lists future formats, but only JSON has a dedicated branch in `src/gruff/cli.py`; non-JSON choices currently render through `TextReporter`.

## Deployment / Operations

Local development uses `uv` through the `Makefile`. CI in `.github/workflows/ci.yml` runs on Python 3.11 and 3.12 with `ruff check`, `ruff format --check`, `mypy`, and `pytest`.

Packaging uses Hatchling from `pyproject.toml`; `uv build` emits artifacts under `dist/`. Pre-commit config mirrors the same checks, but its ruff hook auto-fixes, so non-mutating verification should use the explicit CI commands.
