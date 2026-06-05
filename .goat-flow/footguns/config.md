---
category: config
last_reviewed: 2026-05-30
---

## Footgun: `gruff-py init` emits tiered `thresholds` that contradict the single-threshold contract (ADR-014)

**Status:** active | **Created:** 2026-05-30 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

ADR-014 makes every severity-bearing rubric a single `threshold` + `severity` in public config and forbids `warning`/`error` ranges in generated config, docs, and calibration output. Two surfaces still carry the legacy tiered shape and disagree with the shipped dogfood config:

- `gruff-py init` generates the tiered form. Running `gruff-py init` in an empty dir writes, for every metric rubric, a `thresholds:` block with `warning:`/`error:` pairs (e.g. the cyclomatic-complexity rubric → `warning: 10`, `error: 20`), not `threshold:`/`severity:`. Evidence anchors: `src/gruffpy/command/init_config.py` (search: `def _rule_entry`), confirmed by running the command.
- The built-in rule defaults are tiered: rule files under `src/gruffpy/rule/` (search: `default_thresholds={"warning"`). Meanwhile the committed dogfood config uses the single form: `.gruff-py.yaml` (search: `severity: error`). So `init` output and the committed config disagree on shape.

The non-obvious failure mode is that a reader (human or agent) concludes the project uses warning/error tiers and reproduces that shape in new rules or docs, or "fixes" a config to single-severity only for `init --force` to regenerate the tiered block. Treat the tiered `default_thresholds` and `init` output as drift from ADR-014, not the design. Fixing it is a lockstep move across `init_config.py` (generation), each rule's `default_thresholds`, and the `RuleSettings`/loader fallback (search: `high_value_threshold_match`) so each rubric resolves to one value + one severity. Maintainer rationale: under an agent hook the agent fixes everything down to the lowest gating point, so a second tier is dead weight and one value per rubric is simpler to read and configure. Tracked as a deliverable ("Single severity per rubric") in `.goat-flow/tasks/1.0.0/M02-*`.

## Footgun: ConfigLoader `.get(key, [])` collapses absent into empty, clobbering seeded AnalysisConfig defaults

**Status:** active | **Created:** 2026-05-25 | **Evidence:** ACTUAL_MEASURED

Any new non-empty default added to an `AnalysisConfig` field that is also user-configurable under `[tool.gruff-py.allowlists]` (or another similarly-applied section) can be silently zeroed out by `ConfigLoader` when the user defines that section for an unrelated purpose. The pre-fix shape was `config.with_accepted_abbreviations(tuple(allowlists.get("acceptedAbbreviations", [])))` — when the key was absent, `.get(key, [])` returned `[]` and the `with_…()` setter unconditionally replaced the seeded default with `()`. Evidence anchors: `src/gruffpy/config/loader.py` (search: `_apply_present_allowlists`), `src/gruffpy/config/analysis_config.py` (search: `accepted_abbreviations: tuple[str, ...] = (`), and `tests/unit/config/test_accepted_abbreviations_loader.py` (search: `survive_unrelated_allowlists_section`).

Before adding a non-empty default to any `AnalysisConfig` field, grep `loader.py` for every callsite that reads the corresponding YAML/TOML key and confirm the loader only calls the matching `with_…()` setter when the key is actually present in the user's section. The fix shape is `if "<key>" in allowlists: config = config.with_…(tuple(allowlists["<key>"]))`. Adding tests that drive the loader with the unrelated section populated (e.g. `allowlists.secretPreviews` only) makes this regression observable in unit scope rather than via downstream rule misbehaviour.

## Resolved Entries

## Footgun: `ConfigError` swallowed into `RunDiagnostic` hides config errors from `summary` / structured-output commands

**Status:** resolved | **Created:** 2026-05-27 | **Evidence:** ACTUAL_MEASURED

Catching `ConfigError` inside the analysis runner and returning a `RunDiagnostic(type="config-error", ...)` instead of propagating made every CLI command silently fall back to defaults when a user's `[tool.gruff-py]` / `.gruff-py.yaml` was malformed. The `analyse` text reporter rendered the diagnostic in a `Diagnostics` block, but `summary` (its `_summary_text` / `_summary_payload` deliberately omits diagnostics) and any JSON consumer reading only `findings`/`pillars` saw a clean grade-A run on a config the user had explicitly written wrong. ADR-019 had stated the intent ("loud failure on schema-version absence is preferred over a back-compat shim") but the runner-level swallow defeated it. Reproduced with a `pyproject.toml` containing `[tool.gruff-py]` without `schemaVersion`: `gruff-py summary .` exited 0 with no mention of the missing field. Evidence anchors: `src/gruffpy/analysis/runner.py` (search: `_load_analysis_config`), `src/gruffpy/cli.py` (search: `def _run_analysis_for_cli`), `tests/integration/test_cli_smoke.py` (search: `test_cli_summary_aborts_cleanly_when_config_missing_schema_version`).

Do not reintroduce the `try: ... except ConfigError: return ..., [RunDiagnostic(...)]` pattern for config loading. `ConfigError` carries a user-actionable message (the loader already emits `... run `gruff-py init --force` to regenerate.`) and belongs on the abort path - let it propagate out of `run_analysis` and convert it to `click.ClickException(str(exc))` at the CLI boundary so it surfaces as a clean stderr line with exit 1. The same shape applies to any other "the user's config is structurally invalid" error a future loader adds.
