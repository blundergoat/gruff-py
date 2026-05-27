---
category: config
last_reviewed: 2026-05-27
---

## Footgun: `ConfigError` swallowed into `RunDiagnostic` hides config errors from `summary` / structured-output commands

**Status:** resolved | **Created:** 2026-05-27 | **Evidence:** ACTUAL_MEASURED

Catching `ConfigError` inside the analysis runner and returning a `RunDiagnostic(type="config-error", ...)` instead of propagating made every CLI command silently fall back to defaults when a user's `[tool.gruff-py]` / `.gruff-py.yaml` was malformed. The `analyse` text reporter rendered the diagnostic in a `Diagnostics` block, but `summary` (its `_summary_text` / `_summary_payload` deliberately omits diagnostics) and any JSON consumer reading only `findings`/`pillars` saw a clean grade-A run on a config the user had explicitly written wrong. ADR-019 had stated the intent ("loud failure on schema-version absence is preferred over a back-compat shim") but the runner-level swallow defeated it. Reproduced with a `pyproject.toml` containing `[tool.gruff-py]` without `schemaVersion`: `gruff-py summary .` exited 0 with no mention of the missing field. Evidence anchors: `src/gruffpy/analysis/runner.py` (search: `_load_analysis_config`), `src/gruffpy/cli.py` (search: `def _run_analysis_for_cli`), `tests/integration/test_cli_smoke.py` (search: `test_cli_summary_aborts_cleanly_when_config_missing_schema_version`).

Do not reintroduce the `try: ... except ConfigError: return ..., [RunDiagnostic(...)]` pattern for config loading. `ConfigError` carries a user-actionable message (the loader already emits `... run `gruff-py init --force` to regenerate.`) and belongs on the abort path — let it propagate out of `run_analysis` and convert it to `click.ClickException(str(exc))` at the CLI boundary so it surfaces as a clean stderr line with exit 1. The same shape applies to any other "the user's config is structurally invalid" error a future loader adds.

## Footgun: ConfigLoader `.get(key, [])` collapses absent into empty, clobbering seeded AnalysisConfig defaults

**Status:** active | **Created:** 2026-05-25 | **Evidence:** ACTUAL_MEASURED

Any new non-empty default added to an `AnalysisConfig` field that is also user-configurable under `[tool.gruff-py.allowlists]` (or another similarly-applied section) can be silently zeroed out by `ConfigLoader` when the user defines that section for an unrelated purpose. The pre-fix shape was `config.with_accepted_abbreviations(tuple(allowlists.get("acceptedAbbreviations", [])))` — when the key was absent, `.get(key, [])` returned `[]` and the `with_…()` setter unconditionally replaced the seeded default with `()`. Evidence anchors: `src/gruffpy/config/loader.py` (search: `_apply_present_allowlists`), `src/gruffpy/config/analysis_config.py` (search: `accepted_abbreviations: tuple[str, ...] = (`), and `tests/unit/config/test_accepted_abbreviations_loader.py` (search: `survive_unrelated_allowlists_section`).

Before adding a non-empty default to any `AnalysisConfig` field, grep `loader.py` for every callsite that reads the corresponding YAML/TOML key and confirm the loader only calls the matching `with_…()` setter when the key is actually present in the user's section. The fix shape is `if "<key>" in allowlists: config = config.with_…(tuple(allowlists["<key>"]))`. Adding tests that drive the loader with the unrelated section populated (e.g. `allowlists.secretPreviews` only) makes this regression observable in unit scope rather than via downstream rule misbehaviour.
