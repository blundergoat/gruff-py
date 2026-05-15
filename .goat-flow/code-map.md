# Code Map

## Read In This Order

To get oriented quickly, read these four files in order — they cover the orchestration backbone end to end:

1. `src/gruff/cli.py` — entrypoint, flag wiring, exit-code selection.
2. `src/gruff/rule/registry.py` — what rules exist, how per-unit and project-level rules run, how findings deduplicate.
3. `src/gruff/analysis/schema.py` — the `gruff.analysis.v1` / `gruff.baseline.v1` / `gruff.hotspot.v1` schema strings and `AnalysisReport.to_dict()` shape.
4. `src/gruff/finding/fingerprint.py` — the PHP-compatible fingerprint algorithm.

## Source Tree

- `src/gruff/` = Python package for the CLI analyser.
- `src/gruff/cli.py` = Click entrypoint, orchestration, report rendering choice, dashboard command wiring, and process exit-code logic.
- `src/gruff/__main__.py` = `python -m gruff` entrypoint.
- `src/gruff/version.py` = runtime version string shown by the CLI.
- `src/gruff/analysis/` = report model, diagnostic model, and schema version constants (`gruff.analysis.v1`, `gruff.baseline.v1`, `gruff.hotspot.v1`).
- `src/gruff/command/` = local dashboard HTTP server and self-contained dashboard page renderer.
- `src/gruff/config/` = project config loading for `--config <path>`, `.gruff.yaml`, and `[tool.gruff]` in `pyproject.toml`; rule selection and immutable-style config update helpers.
- `src/gruff/source/` = source file discovery, default ignored directories, lockfile filename filter, configured ignore matching, and `SourceFile` records.
- `src/gruff/parser/` = source parsing into `AnalysisUnit`; Python files receive ASTs and parent links.
- `src/gruff/rule/` = `Rule` ABC, `ProjectRuleProtocol`, definitions, context, registry, enabled-rule execution, deduplication, and stable ordering.
- `src/gruff/rule/size/` = file/class/function length and parameter/attribute count rules.
- `src/gruff/rule/complexity/` = cyclomatic, cognitive, Halstead volume, maintainability index, nesting depth, and NPATH rules.
- `src/gruff/rule/dead_code/` and `src/gruff/rule/waste/` = unused private symbols, empty bodies, unreachable code, redundant variables, and unused imports/parameters.
- `src/gruff/rule/naming/` = intent-layer naming rules (PEP 8 case style is delegated to ruff's `N` rules — see ADR-004).
- `src/gruff/rule/docs/` = docstring presence, parameter/return/raises consistency parsed via `docstring-parser` (ADR-005), TODO density, and missing-README checks.
- `src/gruff/rule/security/` = heuristic AST-level dangerous patterns (eval/exec, unsafe pickle, SQL concat, weak crypto, shell injection, disabled SSL verify, and more).
- `src/gruff/rule/sensitive_data/` = secrets and PHI/PII scanners; subclass `SourceTextRule` and run on text files as well as Python.
- `src/gruff/rule/test_quality/` = pytest-aware test-smell rules; shared scope-detection cache lives in `_test_quality_node_helper`, project-config rules read `pyproject.toml` once via `_pytest_config`.
- `src/gruff/rule/design/` = project-level design rules such as `design.single-implementor-protocol`.
- `src/gruff/finding/` = finding model, severity/confidence/pillar enums, fail thresholds, output-format enum, and gruff-php-compatible fingerprints.
- `src/gruff/scoring/` = score calculation, grade models, per-pillar scores, and top-offender file scores.
- `src/gruff/reporting/` = text, JSON, HTML, Markdown, GitHub annotation, hotspot, and SARIF renderers plus display-only finding filters.

## Tests

- `tests/integration/test_cli_smoke.py` = CLI smoke tests for help, report formats, display filters, schema version, findings, and exit codes.
- `tests/unit/reporting/` = focused reporter and display-filter tests.
- `tests/unit/finding/test_fingerprint.py` = gruff-php fingerprint ground truth and fingerprint stability tests.
- `tests/unit/rule/<pillar>/` = focused per-rule logic tests, one file per rule plus pillar-integration fixtures.
- `tests/unit/rule/test_quality/test_memoisation_gate.py` = invariant test that test-quality rules share a single scope-detection pass per analyse run.
- `tests/unit/config/` = config loading and precedence tests for `.gruff.yaml` and `[tool.gruff]`.

## Project Config

- `pyproject.toml` = package metadata, Hatchling build config, pytest options, ruff config, mypy strict config, and dogfooded `[tool.gruff]` config.
- `.gruff.yaml` = optional project-level overrides; takes precedence over `[tool.gruff]`.
- `uv.lock` = locked Python dependency graph.
- `Makefile` = `uv`-backed development tasks.
- `.pre-commit-config.yaml` = pre-commit hooks for YAML/TOML, whitespace, ruff, ruff-format, and mypy.
- `.github/workflows/ci.yml` = Python 3.11/3.12 CI matrix.
- `package.json` and `package-lock.json` = npm metadata for local GOAT Flow tooling.

## GOAT Flow And Agent Surfaces

- `CLAUDE.md` = Claude Code hot-path project instructions.
- `.claude/skills/` = installed goat-flow skills; copied verbatim by the installer.
- `.claude/settings.json` = Claude Code permissions and deny hook registration.
- `.claude/hooks/` = deny-dangerous hook and self-test script.
- `.goat-flow/config.yaml` = GOAT Flow version and enabled agent list.
- `.goat-flow/architecture.md` = cold-path system architecture.
- `.goat-flow/code-map.md` = this repository map.
- `.goat-flow/glossary.md` = project vocabulary.
- `.goat-flow/footguns/` = durable codebase traps with evidence.
- `.goat-flow/lessons/` = durable workflow mistakes when real incidents exist.
- `.goat-flow/patterns/` = reusable project approaches.
- `.goat-flow/decisions/` = ADRs when architectural decisions need durable context.
- `.goat-flow/skill-reference/` = shared skill contract references.
- `.goat-flow/skill-playbooks/` = on-demand tool availability playbooks.
- `.goat-flow/logs/sessions/` = local session continuity logs.
- `.goat-flow/tasks/` and `.goat-flow/scratchpad/` = local milestone state and temporary notes.

## Generated Or Never-Edit Paths

- `node_modules/` = npm dependency cache for GOAT Flow tooling; do not edit vendored package files.
- `dist/` = generated package artifacts from `uv build`; do not edit.
- `.venv/` = local Python virtual environment managed by `uv`; do not edit.
- `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `__pycache__/` = local tool caches; do not edit.
