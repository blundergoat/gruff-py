# Architecture

## Mission

gruff-py governs **AI-generated code for human sign-off**. The operating assumption is that a coding agent produced the change and a reviewer who did not write it must read, review, and trust it, so the rule catalogue, severities, and scoring exist to raise that reviewer's confidence — not to enforce abstract style. As a coding-agent hook it **guides** through advisory findings and **forces** through `--fail-on`-gated warning and error findings toward three outcomes:

- **Verifiable** — control flow a reviewer can follow and check against the stated requirement (the `size`, `complexity`, and `naming` pillars).
- **Secure where review is weakest** — dangerous calls, misconfiguration, and leaked secrets the eye skips (the `security` and `sensitive-data` pillars).
- **Tested for real** — behaviour-exercising tests rather than assertion-free or mock-only ceremony that inflates coverage (the `test-quality` pillar).

This is the reason the `documentation` pillar requires doc comments even on private one-liners: agents routinely produce code that superficially works while misunderstanding the requirement, so forcing the agent to state intent, usage, contract, and failure behaviour gives the reviewer a prose contract to check the implementation against — a doc/code mismatch is itself a "look closer" signal. The same mission explains the severity order (`SECURITY` > `CORRECTNESS` > `INTEGRATION` > `PERFORMANCE` > `STYLE`) and why `test-quality` leans toward catching low-signal bloat. gruff-py is heuristic static analysis and complements `ruff`, `mypy`, `pytest`, dedicated scanners, and human review rather than replacing them. Recorded as a decision in ADR-022; the agent-hook tuning policy it implies is ADR-021.

## System Overview

gruff-py is a Click-based Python CLI that analyses project files and emits text, JSON, HTML, Markdown, GitHub annotation, hotspot, and SARIF quality reports. It also ships a dependency-free local dashboard server that embeds the HTML report in a full-window browser shell. `src/gruffpy/cli.py` orchestrates config loading, source discovery, parsing, rule execution, scoring, reporting, display filtering, dashboard startup, and exit-code selection; domain objects live in focused packages under `src/gruffpy/`.

The main runtime components are `ConfigLoader`, `SourceDiscovery`, `PythonFileParser`, `RuleRegistry`, `ProjectRuleProtocol`, `ScoreCalculator`, `FindingDisplayFilter`, `DashboardPageRenderer`, the local dashboard server under `src/gruffpy/command/`, and the reporter classes under `src/gruffpy/reporting/`. Rules are isolated behind per-unit and project-level interfaces so the catalogue grows without making CLI parsing or report rendering own rule-specific behaviour.

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

The compatibility contracts are explicit in `src/gruffpy/analysis/schema.py` and `src/gruffpy/finding/fingerprint.py`. Fingerprints intentionally reproduce gruff-php byte behaviour, including PHP-style slash escaping before hashing. `Finding.to_dict()` emits both `fingerprint` (line-precise identity used by baselines and SARIF) and `stableIdentity` (line-insensitive identity hashed from `[ruleId, file, symbol]`, falling back to `[ruleId, file, message]` when `symbol` is `None`) — external diff tooling that wants "the same logical finding across line shifts" reads `stableIdentity`; baseline matching reads `fingerprint`. See ADR-020 for the input set and cross-port pairing.

## Rules And Scoring

`RuleRegistry.defaults()` instantiates the full rule catalogue: 114 rules across
11 active pillars (`size`, `complexity`, `maintainability`, `dead-code`,
`naming`, `documentation`, `security`, `sensitive-data`, `test-quality`,
`design`, and `modernisation`). Each pillar lives under
`src/gruffpy/rule/<pillar>/`, with legacy `waste.*` rule IDs emitting under the
`dead-code` pillar. `ProjectRuleProtocol` handles cross-file rules such as
`design.single-implementor-protocol`. Overlapping `size.*` and `complexity.*`
findings on one symbol are billed once by `ScoreCalculator`'s correlated-rule
clustering (`CORRELATED_COMPLEXITY_RULES`); the `design.god-method` composite
that previously named that overlap was retired (ADR-024).
`AnalysisConfig.from_registry()` snapshots each rule's default settings;
selection and per-rule overrides are applied by `ConfigLoader`.

Rules subclassing `SourceTextRule` additionally run on `.env`/`.toml`/`.yaml`/`.json`/`.ini`/`.conf` text files - the secret/PHI scanners under `sensitive-data.*` use this seam. Several test-quality rules read `pyproject.toml` once per run via `_pytest_config`; scope detection for test-quality rules is memoised through `_test_quality_node_helper` so the catalogue computes per-unit scope exactly once.

`ScoreCalculator` scores the declared pillars plus any pillar found in findings, using the two-axis severity × confidence weight model (severity weights 12/4/1, confidence 1.0/0.75/0.5, pillar multiplier ×4, file multiplier ×5). Grades land at 90/80/70/60 for A/B/C/D, anything below is F. The output is a composite grade, per-pillar grades, and top-offender file grades.

## Reporting And Schemas

`JsonReporter` serializes `AnalysisReport.to_dict()` with four-space indentation, slashes not escaped, and non-ASCII escaped, matching the PHP reference's `JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES` behaviour for shared keys. `TextReporter`, `HtmlReporter`, `MarkdownReporter`, `GithubAnnotationsReporter`, `HotspotReporter`, and `SarifReporter` render the same `AnalysisReport` for human, CI, and code-scanning consumers.

`FindingDisplayFilter` applies display-only filters after scoring and exit-code selection, recording the active filter set under `run.filters`. The `gruff-py.hotspot.v1` schema is declared in `src/gruffpy/analysis/schema.py` and emitted by `HotspotReporter`.

`summary --group-by=rule` replaces the default `Top rules:` block with a count / rule-id / severity / confidence table sourced from `AnalysisReport.finding_counts_by_rule()`; the JSON output additively gains a `groupedRules` field while `topRules` stays unchanged for back-compat. When `analyse --format text` produces at least `outputVolumeHintThreshold` findings (default 50; set to 0 to disable), `TextReporter` appends a footer hint pointing at the grouped summary mode. The threshold lives on `AnalysisConfig.output_volume_hint_threshold` and is configurable via the top-level `outputVolumeHintThreshold:` key.

`list-rules` accepts an optional positional `<rule_id>`. Without it, the command renders today's catalogue (table or JSON). With a known id, it renders an explain-mode detail view of one rule's header, rationale, fix guidance, examples, default options (with one-line `RuleDocs.option_descriptions` text), escape hatches, false-positive shapes (`RuleDocs.false_positive_shapes`), and related rules (`RELATED_RULES` map in `src/gruffpy/rule/catalog.py`). `--format table` coerces to text for the single-rule view since one record has no table. Unknown ids exit 1 with `difflib.get_close_matches` suggestions.

## Deployment / Operations

Local development uses `uv` through the `Makefile`. CI in `.github/workflows/ci.yml` runs on Python 3.11 and 3.12 with `ruff check`, `ruff format --check`, `mypy`, and `pytest`.

Packaging uses Hatchling from `pyproject.toml`; `uv build` emits artifacts under `dist/`. Pre-commit config mirrors the same checks, but its ruff hook auto-fixes, so non-mutating verification should use the explicit CI commands.

The dashboard uses only the Python standard library and inline HTML/CSS/JS. It does not add a frontend build step or runtime asset pipeline.
