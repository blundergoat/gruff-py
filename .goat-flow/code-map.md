# Code Map

## Read In This Order

To get oriented quickly, read these four files in order - they cover the orchestration backbone end to end:

1. `src/gruffpy/cli.py` - entrypoint, command registration, exit-code selection; the shared flag definitions it wires live in `src/gruffpy/cli_options.py`.
2. `src/gruffpy/rule/registry.py` - what rules exist, how per-unit and project-level rules run, how findings deduplicate.
3. `src/gruffpy/analysis/schema.py` - the `gruff.analysis.v2` / `gruff-py.baseline.v1` / `gruff-py.hotspot.v1` schema strings used by report models.
4. `src/gruffpy/finding/fingerprint.py` - the PHP-compatible fingerprint algorithm.

## Source Tree

- `src/gruffpy/` = Python package for the CLI analyser.
- `src/gruffpy/cli.py` = Click entrypoint, orchestration, report rendering choice, dashboard command wiring, and process exit-code logic.
- `src/gruffpy/cli_options.py` = shared Click option definitions and the option-to-request translation used by every analysing subcommand; it is the largest CLI module, so flag work usually lands here rather than in `cli.py`.
- `src/gruffpy/cli_dashboard.py`, `src/gruffpy/cli_hook.py`, `src/gruffpy/cli_list_rules.py`, `src/gruffpy/cli_menu.py`, `src/gruffpy/cli_migrate_config.py`, `src/gruffpy/cli_state.py`, `src/gruffpy/cli_summary.py` = per-subcommand implementations extracted from `cli.py` to keep it under the `size.file-length` error threshold; add new subcommand bodies here, not in `cli.py`.
- `src/gruffpy/hook_contract.py` = the `gruff.hook.v2` projection and its stable-identity scheme, consumed by `gruff-py hook` and by the shared `.goat-flow/hooks/gruff-code-quality.sh` agent hook.
- `src/gruffpy/suppression/` = tokenizer-backed `# gruff: disable=` / `disable-next=` / `disable-file=` comment parser plus the central post-execution finding filter applied by `src/gruffpy/analysis/runner.py` (ADR-008).
- `src/gruffpy/__main__.py` = `python -m gruffpy` entrypoint.
- `src/gruffpy/version.py` = runtime version string shown by the CLI.
- `src/gruffpy/analysis/` = report, request, runner, diagnostic, baseline, changed-region, and schema models; native analysis is `gruff.analysis.v2`, baseline is `gruff-py.baseline.v1`, and hotspot is `gruff-py.hotspot.v1`. Only the analysis and summary strings are shared with the sibling ports - see `.goat-flow/learning-loop/footguns/compatibility.md` before touching the baseline or hotspot strings.
- `src/gruffpy/command/` = focused command helpers for init/migration, generated rule docs, ignore verdicts, calibration, and the local dashboard server/page.
- `src/gruffpy/config/` = project config loading in this order: explicit `--config`, modern `.gruff-py.yaml`, legacy `.gruff.yaml`, modern `[tool.gruff-py]`, legacy `[tool.gruff]`, then defaults; rule selection and immutable-style config update helpers live here too.
- `src/gruffpy/source/` = source file discovery, default ignored directories, lockfile filename filter, configured ignore matching, and `SourceFile` records.
- `src/gruffpy/parser/` = source parsing into `AnalysisUnit`; Python files receive ASTs and parent links.
- `src/gruffpy/rule/` = `Rule` ABC, `ProjectRuleProtocol`, definitions, context, registry, enabled-rule execution, deduplication, and stable ordering.
- `src/gruffpy/rule/size/` = file/class/function length and parameter/attribute count rules.
- `src/gruffpy/rule/complexity/` = cyclomatic, cognitive, Halstead volume, nesting depth, and the maintainability-index implementation; NPATH is retired, and maintainability index emits under the separate `maintainability` pillar.
- `src/gruffpy/rule/correctness/` = unsafe numeric-coercion and substring-vocabulary checks for runtime failure or routing mistakes.
- `src/gruffpy/rule/dead_code/` and `src/gruffpy/rule/waste/` = unused private symbols, empty bodies, unreachable code, redundant variables, and unused imports/parameters.
- `src/gruffpy/rule/modernisation/` = the registered f-string conversion candidate rule.
- `src/gruffpy/rule/naming/` = intent-layer naming rules (PEP 8 case style is delegated to ruff's `N` rules - see ADR-004).
- `src/gruffpy/rule/docs/` = docstring presence, parameter/return/raises consistency parsed via `docstring-parser` (ADR-005), TODO density, and missing-README checks.
- `src/gruffpy/rule/security/` = heuristic AST-level dangerous patterns (eval/exec, unsafe pickle, SQL concat, weak crypto, shell injection, disabled SSL verify, and more).
- `src/gruffpy/rule/sensitive_data/` = secrets and PHI/PII scanners; subclass `SourceTextRule` and run on text files as well as Python.
- `src/gruffpy/rule/test_quality/` = pytest-aware test-smell rules; shared scope-detection cache lives in `_test_quality_node_helper`, project-config rules read `pyproject.toml` once via `_pytest_config`.
- `src/gruffpy/rule/design/` = project-level design rules such as `design.single-implementor-protocol`.
- `src/gruffpy/finding/` = finding model, severity/confidence/pillar enums, fail thresholds, output-format enum, and gruff-php-compatible fingerprints.
- `src/gruffpy/scoring/` = score calculation, grade models, per-pillar scores, and top-offender file scores.
- `src/gruffpy/reporting/` = text, JSON, HTML, Markdown, GitHub annotation, hotspot, and SARIF renderers plus display-only finding filters.

## Tests

- `tests/integration/test_cli_smoke.py` = CLI smoke tests for help, report formats, display filters, schema version, findings, and exit codes.
- `tests/unit/reporting/` = focused reporter and display-filter tests.
- `tests/unit/finding/test_fingerprint.py` = gruff-php fingerprint ground truth and fingerprint stability tests.
- `tests/unit/rule/<pillar>/` = focused per-rule logic tests, one file per rule plus pillar-integration fixtures.
- `tests/unit/rule/test_quality/test_memoisation_gate.py` = invariant test that test-quality rules share a single scope-detection pass per analyse run.
- `tests/unit/config/` = config loading and precedence tests for modern/legacy YAML and modern/legacy `pyproject.toml` tool tables.

## Project Config

- `pyproject.toml` = package metadata, Hatchling build config, pytest options, ruff config, mypy strict config, and dogfooded `[tool.gruff-py]` config.
- `.gruff-py.yaml` = the repository's modern YAML config; legacy `.gruff.yaml` remains readable, and either YAML source takes precedence over `pyproject.toml` discovery.
- `uv.lock` = locked Python dependency graph.
- `Makefile` = `uv`-backed development tasks.
- `.pre-commit-config.yaml` = pre-commit hooks for YAML/TOML, whitespace, ruff, ruff-format, and mypy.
- `.github/workflows/ci.yml` = Python 3.11/3.12 CI matrix.
- `package.json` and `package-lock.json` = npm metadata for local GOAT Flow tooling.

## GOAT Flow And Agent Surfaces

- `AGENTS.md` = Codex hot-path project instructions and GOAT Flow `1.15.1` declaration.
- `.agents/skills/` = installed Codex goat-flow skills; `.agents/hooks.json` is a separate shared-agent hook surface.
- `.codex/` = Codex-specific configuration and active hook registration in `.codex/hooks.json`.
- `CLAUDE.md` = separate Claude peer instructions and GOAT Flow `1.15.1` declaration.
- `.claude/skills/` and `.claude/settings.json` = the coexisting Claude skill and permission surfaces.
- `.github/copilot-instructions.md` = standalone Copilot peer instructions and GOAT Flow `1.15.1` declaration.
- `.github/skills/` = installed Copilot goat-flow skills; `.github/hooks/` is that surface's hook directory.
- `.goat-flow/hooks/` = shared deny-dangerous and gruff-code-quality hook scripts, with policy patterns and self-test under `deny-dangerous/`.
- `.goat-flow/config.yaml` = GOAT Flow version, skill-install mode, and hook enablement state.
- `.goat-flow/architecture.md` = cold-path system architecture.
- `.goat-flow/code-map.md` = this repository map.
- `.goat-flow/glossary.md` = project vocabulary.
- `.goat-flow/learning-loop/footguns/` = durable codebase traps with evidence.
- `.goat-flow/learning-loop/lessons/` = durable workflow mistakes when real incidents exist.
- `.goat-flow/learning-loop/patterns/` = reusable project approaches.
- `.goat-flow/learning-loop/decisions/` = ADRs when architectural decisions need durable context.
- `.goat-flow/skill-docs/` = shared skill contract references.
- `.goat-flow/skill-docs/playbooks/` = indexed top-level playbooks: `browser-use.md`, `changelog.md`, `code-comments.md`, `gruff-code-quality.md`, `hook-policy-testing.md`, `observability.md`, `page-capture.md`, `release-notes.md`, `skill-playbook-authoring-sync.md`, and `writing-style.md`.
- `.goat-flow/logs/sessions/` = local session continuity logs.
- `.goat-flow/plans/` and `.goat-flow/scratchpad/` = local milestone state and temporary notes.
- GOAT Flow package metadata records its internal src/dashboard/views/ HTML view inventory as (about, home, hooks, plans, projects, prompts, quality, settings, setup, skills, workspace); this is installer/reference metadata, not gruff-py source.

All four tracked agent instruction surfaces currently declare GOAT Flow
`1.15.1`: `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, and the
`.goat-flow/config.yaml` workspace record, alongside the shared references,
hooks, and local CLI. Each instruction file stays standalone and owns its own
skills directory; a declaration here that disagrees with `.goat-flow/config.yaml`
is drift to fix, not peer metadata to record.

## Generated Or Never-Edit Paths

- `node_modules/` = npm dependency cache for GOAT Flow tooling; do not edit vendored package files.
- `dist/` = generated package artifacts from `uv build`; do not edit.
- `.venv/` = local Python virtual environment managed by `uv`; do not edit.
- `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `__pycache__/` = local tool caches; do not edit.
