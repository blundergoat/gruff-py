---
category: config
last_reviewed: 2026-08-22
---

## Footgun: ConfigLoader `.get(key, [])` collapses absent into empty, clobbering seeded AnalysisConfig defaults

**Status:** active | **Created:** 2026-05-25 | **Evidence:** ACTUAL_MEASURED

Any new non-empty default added to an `AnalysisConfig` field that is also user-configurable under `[tool.gruff-py.allowlists]` (or another similarly-applied section) can be silently zeroed out by `ConfigLoader` when the user defines that section for an unrelated purpose. The pre-fix shape was `config.with_accepted_abbreviations(tuple(allowlists.get("acceptedAbbreviations", [])))` — when the key was absent, `.get(key, [])` returned `[]` and the `with_…()` setter unconditionally replaced the seeded default with `()`. Evidence anchors: `src/gruffpy/config/loader.py` (search: `_apply_present_allowlists`), `src/gruffpy/config/analysis_config.py` (search: `accepted_abbreviations: tuple[str, ...] = (`), and `tests/unit/config/test_accepted_abbreviations_loader.py` (search: `survive_unrelated_allowlists_section`).

Before adding a non-empty default to any `AnalysisConfig` field, grep `loader.py` for every callsite that reads the corresponding YAML/TOML key and confirm the loader only calls the matching `with_…()` setter when the key is actually present in the user's section. The fix shape is `if "<key>" in allowlists: config = config.with_…(tuple(allowlists["<key>"]))`. Adding tests that drive the loader with the unrelated section populated (e.g. `allowlists.secretPreviews` only) makes this regression observable in unit scope rather than via downstream rule misbehaviour.

## Footgun: a registry-validated, report-counted config section hits two import walls in `gruffpy`

**Status:** active | **Created:** 2026-08-22 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** where a new config validator gets rule metadata, and where a new report value object is defined
**Trigger phase:** SCOPE

The `sensitiveExclusions` section (FAMILY-CONTRACT section 13a) needs two facts the obvious imports cannot supply, and both failures are import-time, not test-time. First, its validator must reject a rule id outside the sensitive-data pillar, which needs `RuleRegistry` - but adding `from gruffpy.rule.registry import RuleRegistry` to `src/gruffpy/config/loader.py` and running `python -c "import gruffpy.rule.registry"` raised `ImportError: cannot import name 'RuleContext' from partially initialized module 'gruffpy.rule.context'`, because `gruffpy/config/__init__.py` imports the loader and `gruffpy.rule.context` imports `gruffpy.config.analysis_config`. Second, the audit row the counter fills is consumed by `src/gruffpy/analysis/report.py` and produced by the suppression channel; defining it in `gruffpy/suppression/` and importing it from the report raised `ImportError: cannot import name 'SuppressionSummary' from partially initialized module 'gruffpy.suppression.sensitive_exclusion_filter'` through the chain `config.loader` to `analysis.schema` to `analysis.__init__` to `analysis.report`.

Both were resolved by injection rather than import. The pillar fact is captured once at registry projection time in `src/gruffpy/config/analysis_config.py` (search: `sensitive_data_rule_ids`), where `from_registry` already walks every definition, and the validator reads it off the config it was handed: `src/gruffpy/config/sensitive_exclusions.py` (search: `def parse_sensitive_exclusions`). The audit row lives with the other report value objects in `src/gruffpy/analysis/suppression_summary.py` (search: `class SuppressionSummary`), and the suppression channel imports it downward: `src/gruffpy/suppression/sensitive_exclusion_filter.py` (search: `def partition_sensitive_exclusions`). The direction that works is `rule` to `config` and `suppression` to `analysis`, never the reverse.

Before adding any config validator that needs rule metadata, or any suppression channel that publishes a report field, plan for that direction from the start. Rule facts reach the config layer through a field on `AnalysisConfig` filled by `from_registry`; report value objects belong under `src/gruffpy/analysis/`, and the channel that fills them imports them, not the other way round.

**Portability question for the family.** gruff-rs validates its exclusions with the registry in hand inside its own config loader - its exclusion parser (search: `fn parse_exclusion_rule`) calls `rules::builtin_registry()` directly - so its validator can name the offending rule and pillar from one place, while gruff-py must pre-compute the pillar set one layer earlier. That difference is invisible while conformance asserts only the rejection set, and becomes visible the moment it asserts diagnostic text: the same rejection is phrased by rs as an exclusion-selector error and by py as a `Config key "sensitiveExclusions[0].rule"` error. The family has to decide whether section 13a's "distinct fatal configuration diagnostic naming the entry index and the offending key" fixes the wording or only the fields, before a cross-port fixture can compare messages rather than outcomes.

## Resolved Entries

## Footgun: `gruff-py init` emitted tiered `thresholds` that contradicted the single-threshold contract (ADR-014)

**Status:** resolved | **Created:** 2026-05-30 | **Resolved:** 2026-05-31 | **Evidence:** ACTUAL_MEASURED

ADR-014 makes every severity-bearing rubric a single `threshold` + `severity` and forbids `warning`/`error` ranges in generated config. When this was filed, `gruff-py init` wrote a tiered `thresholds:` block with `warning:`/`error:` pairs for every metric rubric, and the built-in rule defaults carried the same tiered shape — so `init` output disagreed with the single-form committed dogfood config. Resolved by `902ba46` ("unify threshold handling by replacing multiple thresholds with a single severity threshold across rules"), which landed the "Single severity per rubric" deliverable. Verified 2026-06-06: `gruff-py init` in an empty dir now emits `threshold:`/`severity:` for every rubric (e.g. cyclomatic → `threshold: 20`, `severity: error`), matching `.gruff-py.yaml` (search: `severity: error`); the only surviving `thresholds:` block holds maintainability-index knobs (`cyclomatic_warning` etc.), not a severity tier. The anchor `default_thresholds={"warning"` no longer exists in `src/gruffpy/rule/` (zero matches), and no rule default carries `"warning"`/`"error"` keys.

Do not reintroduce a tiered `warning`/`error` rubric in `src/gruffpy/command/init_config.py` (search: `def _rule_entry`) or in rule defaults. `_rule_entry` emits `threshold` + `severity` from `settings.severity_threshold` and reserves the `thresholds:` map for non-severity semantic knobs (`settings.thresholds`). Any new severity-bearing rubric resolves to exactly one value plus one severity per ADR-014.

## Footgun: `ConfigError` swallowed into `RunDiagnostic` hides config errors from `summary` / structured-output commands

**Status:** resolved | **Created:** 2026-05-27 | **Evidence:** ACTUAL_MEASURED

Catching `ConfigError` inside the analysis runner and returning a `RunDiagnostic(type="config-error", ...)` instead of propagating made every CLI command silently fall back to defaults when a user's `[tool.gruff-py]` / `.gruff-py.yaml` was malformed. The `analyse` text reporter rendered the diagnostic in a `Diagnostics` block, but `summary` (its `_summary_text` / `_summary_payload` deliberately omits diagnostics) and any JSON consumer reading only `findings`/`pillars` saw a clean grade-A run on a config the user had explicitly written wrong. ADR-019 had stated the intent ("loud failure on schema-version absence is preferred over a back-compat shim") but the runner-level swallow defeated it. Reproduced with a `pyproject.toml` containing `[tool.gruff-py]` without `schemaVersion`: `gruff-py summary .` exited 0 with no mention of the missing field. Evidence anchors: `src/gruffpy/analysis/runner.py` (search: `_load_analysis_config`), `src/gruffpy/cli.py` (search: `def _run_analysis_for_cli`), `tests/integration/test_cli_smoke.py` (search: `test_cli_summary_aborts_cleanly_when_config_missing_schema_version`).

Do not reintroduce the `try: ... except ConfigError: return ..., [RunDiagnostic(...)]` pattern for config loading. `ConfigError` carries a user-actionable message (the loader already emits `... run `gruff-py init --force` to regenerate.`) and belongs on the abort path - let it propagate out of `run_analysis` and convert it to `click.ClickException(str(exc))` at the CLI boundary so it surfaces as a clean stderr line with exit 1. The same shape applies to any other "the user's config is structurally invalid" error a future loader adds.
