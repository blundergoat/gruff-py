# Code Map

## Hot Paths

- `src/gruff/` = Python package for the CLI analyser.
- `src/gruff/cli.py` = Click entrypoint, orchestration, report rendering choice, and process exit-code logic.
- `src/gruff/__main__.py` = `python -m gruff` entrypoint.
- `src/gruff/version.py` = runtime version string shown by the CLI.
- `src/gruff/analysis/` = report model, diagnostic model, and schema version constants.
- `src/gruff/config/` = `[tool.gruff]` TOML loading, validation, rule selection, and immutable-style config update helpers.
- `src/gruff/source/` = source file discovery, default ignored directories, configured ignore matching, and `SourceFile` records.
- `src/gruff/parser/` = source parsing into `AnalysisUnit`; Python files receive ASTs and parent links.
- `src/gruff/rule/` = rule interface, definitions, context, registry, and enabled-rule execution.
- `src/gruff/rule/size/` = size pillar rules; currently `FileLengthRule`.
- `src/gruff/finding/` = finding model, severity/confidence/pillar enums, fail thresholds, output-format enum, and gruff-php-compatible fingerprints.
- `src/gruff/scoring/` = score calculation, grade models, per-pillar scores, and top-offender file scores.
- `src/gruff/reporting/` = text and JSON renderers.

## Tests

- `tests/integration/test_cli_smoke.py` = CLI smoke tests for help, JSON/text output, schema version, findings, and exit codes.
- `tests/unit/finding/test_fingerprint.py` = gruff-php fingerprint ground truth and fingerprint stability tests.
- `tests/unit/rule/size/test_file_length_rule.py` = focused `FileLengthRule` threshold, severity, remediation, and metadata tests.

## Project Config

- `pyproject.toml` = package metadata, Hatchling build config, pytest options, ruff config, mypy strict config, and dogfooded `[tool.gruff]` config.
- `uv.lock` = locked Python dependency graph.
- `Makefile` = common `uv`-backed development tasks; `make lint` auto-fixes.
- `.pre-commit-config.yaml` = pre-commit hooks for YAML/TOML checks, whitespace, ruff, ruff-format, and mypy.
- `.github/workflows/ci.yml` = Python 3.11/3.12 CI matrix running install, lint, format check, typecheck, and tests.
- `package.json` and `package-lock.json` = npm metadata used for local GOAT Flow tooling.

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
