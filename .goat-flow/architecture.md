# Architecture

## System Overview

gruff-py is a Click-based Python CLI that analyses project files and emits text, JSON, HTML, Markdown, GitHub annotation, hotspot, and SARIF quality reports. It also ships a dependency-free local dashboard server that embeds the HTML report in a full-window browser shell. `src/gruffpy/cli.py` orchestrates config loading, source discovery, parsing, rule execution, scoring, reporting, display filtering, dashboard startup, and exit-code selection; domain objects live in focused packages under `src/gruffpy/`.

The main runtime components are `ConfigLoader`, `SourceDiscovery`, `PythonFileParser`, `RuleRegistry`, `ProjectRuleProtocol`, `CompositeFindingFactory`, `ScoreCalculator`, `FindingDisplayFilter`, `DashboardPageRenderer`, the local dashboard server under `src/gruffpy/command/`, and the reporter classes under `src/gruffpy/reporting/`. Rules are isolated behind per-unit and project-level interfaces so the catalogue grows without making CLI parsing or report rendering own rule-specific behaviour.

## Request Flow

Representative command path: `gruff-py analyse src/ --format json` enters `src/gruffpy/cli.py`, builds default rule settings from `RuleRegistry.defaults()`, loads project config via `ConfigLoader` (precedence: `--config <path>`, then `.gruff.yaml` in the project root, then `[tool.gruff-py]` in `pyproject.toml`), discovers Python and text files with `SourceDiscovery`, parses Python files with `PythonFileParser`, runs enabled per-unit and project-level rules through `RuleRegistry.analyse()`, synthesises composite findings, calculates a score with `ScoreCalculator`, applies display-only filters, renders the `AnalysisReport` with the selected reporter, and exits with `0`, `1`, or `2` based on diagnostics and `--fail-on`.

Dashboard path: `gruff-py dashboard src/` builds an initial `DashboardState`, starts a stdlib `ThreadingHTTPServer` on loopback by default, serves `/` as a self-contained dark dashboard shell, and serves `/scan` by calling the same `run_analysis()` helper used by `analyse` before rendering `HtmlReporter`. Scan metadata is injected into the iframe report as HTML-safe JSON so the parent shell can show exit code, duration, project root, and the equivalent `gruff-py analyse --format html` command.

Unknown keys in `[tool.gruff-py]` or `.gruff.yaml` reject strictly with a `config-error` diagnostic. Parse or config diagnostics are part of the report and force exit code `2`. Findings at or above the selected `FailThreshold` force exit code `1`; clean runs exit `0`.

## Auth / Trust Boundaries

There is no authentication layer, service account, or outbound network request. Trust boundaries are local filesystem inputs: user-supplied paths, `--config`, `pyproject.toml`, and source files read by the CLI.

`gruff-py dashboard` starts a long-running local HTTP server only when explicitly requested. It binds to `127.0.0.1` by default, has no authentication, and should be treated as a local development UI rather than a shared service. Dashboard HTML, iframe metadata, loading frames, and error frames escape interpolated values before rendering.

`.claude/settings.json` and `.claude/hooks/deny-dangerous.sh` protect Claude Code from secret reads/writes and dangerous shell operations during agent sessions. Application runtime does not enforce those agent guardrails.

## Data Flow

Durable project configuration lives in `pyproject.toml`; package resolution is locked by `uv.lock`. Runtime analysis state is in memory: discovered `SourceFile` objects become `AnalysisUnit` objects, rules produce `Finding` objects, and `AnalysisReport.to_dict()` provides the JSON schema payload.

The compatibility contracts are explicit in `src/gruffpy/analysis/schema.py` and `src/gruffpy/finding/fingerprint.py`. Fingerprints intentionally reproduce gruff-php byte behaviour, including PHP-style slash escaping before hashing.

## Rules And Scoring

`RuleRegistry.defaults()` instantiates the full rule catalogue: 103 rules across 10 active pillars (`size`, `complexity` + `maintainability`, `dead-code` + `waste`, `naming`, `documentation`, `security`, `sensitive-data`, `test-quality`, `design`). Each pillar lives under `src/gruffpy/rule/<pillar>/`. A subset of `test-quality` rules ship default-off and are opted in via `[tool.gruff-py.rules]`. `ProjectRuleProtocol` handles cross-file rules such as `design.single-implementor-protocol`, while `CompositeFindingFactory` synthesises `design.god-method` findings post-pass when size + complexity overlap on a symbol. `modernisation` is declared in the score model but its rule catalogue is still being built. `AnalysisConfig.from_registry()` snapshots each rule's default settings; selection and per-rule overrides are applied by `ConfigLoader`.

Rules subclassing `SourceTextRule` additionally run on `.env`/`.toml`/`.yaml`/`.json`/`.ini`/`.conf` text files - the secret/PHI scanners under `sensitive-data.*` use this seam. Several test-quality rules read `pyproject.toml` once per run via `_pytest_config`; scope detection for test-quality rules is memoised through `_test_quality_node_helper` so the catalogue computes per-unit scope exactly once.

`ScoreCalculator` scores the declared pillars plus any pillar found in findings, using the two-axis severity × confidence weight model (severity weights 12/4/1, confidence 1.0/0.75/0.5, pillar multiplier ×4, file multiplier ×5). Grades land at 90/80/70/60 for A/B/C/D, anything below is F. The output is a composite grade, per-pillar grades, and top-offender file grades.

## Reporting And Schemas

`JsonReporter` serializes `AnalysisReport.to_dict()` with four-space indentation, slashes not escaped, and non-ASCII escaped, matching the PHP reference's `JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES` behaviour for shared keys. `TextReporter`, `HtmlReporter`, `MarkdownReporter`, `GithubAnnotationsReporter`, `HotspotReporter`, and `SarifReporter` render the same `AnalysisReport` for human, CI, and code-scanning consumers.

`FindingDisplayFilter` applies display-only filters after scoring and exit-code selection, recording the active filter set under `run.filters`. The `gruff-py.hotspot.v1` schema is declared in `src/gruffpy/analysis/schema.py` and emitted by `HotspotReporter`.

## Deployment / Operations

Local development uses `uv` through the `Makefile`. CI in `.github/workflows/ci.yml` runs on Python 3.11 and 3.12 with `ruff check`, `ruff format --check`, `mypy`, and `pytest`.

Packaging uses Hatchling from `pyproject.toml`; `uv build` emits artifacts under `dist/`. Pre-commit config mirrors the same checks, but its ruff hook auto-fixes, so non-mutating verification should use the explicit CI commands.

The dashboard uses only the Python standard library and inline HTML/CSS/JS. It does not add a frontend build step or runtime asset pipeline.
