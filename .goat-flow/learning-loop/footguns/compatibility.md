---
category: compatibility
last_reviewed: 2026-06-09
---

## Footgun: Finding fingerprints depend on PHP-style JSON bytes

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

The fingerprint algorithm in `src/gruffpy/finding/fingerprint.py` is deliberately not plain `json.dumps(...).sha256()`. Evidence anchors: `src/gruffpy/finding/fingerprint.py` (search: `encoded = encoded.replace("/", r"\/")`) and `tests/unit/finding/test_fingerprint.py` (search: `PHP_GROUND_TRUTH`).

The non-obvious failure mode is that "simplifying" JSON encoding, changing slash escaping, expanding hashed fields, or reordering the payload breaks compatibility with gruff-php baselines while most local CLI output still appears normal. Any edit here must run `uv run pytest tests/unit/finding/test_fingerprint.py`.

## Footgun: hook and analysis `stableIdentity` use different input sets for symbol-less file/project findings

**Status:** active | **Created:** 2026-06-09 | **Evidence:** ACTUAL_MEASURED

Two identity schemes share the field name `stableIdentity` but diverge. The analysis/report identity (`src/gruffpy/finding/fingerprint.py`, search: `def stable_identity_for`) hashes `[ruleId, file, message]` whenever `symbol is None` (ADR-020). The `gruff.hook.v1` identity (`src/gruffpy/hook_contract.py`, search: `def _hook_stable_identity`) instead hashes `[ruleId, file, scope]` for `file`/`project` scope and only falls back to `message` for `line` scope. So one `size.file-length` finding gets a message-keyed digest in `analyse --format json` and a scope-keyed digest in hook mode.

The non-obvious failure mode: feeding an `analyse --format json` report to `gruff-py hook --baseline` should suppress that report's findings, but file/project findings (`size.file-length`, `docs.missing-module-docstring`, `docs.todo-density`, ...) re-surfaced because the analysis digest never matched the hook digest. The hook reader must rebuild the hook identity from each baseline row's fields, not trust the row's `stableIdentity` string: `src/gruffpy/hook_contract.py` (search: `def _stable_identity_from_row`, search: `def _row_scope`) reconstructs scope from the rule id and line exactly as `_scope_for_finding` does, because analysis rows carry no `scope` field. Regression: `tests/integration/test_hook_contract.py` (search: `test_hook_baseline_accepts_analysis_format_json_for_file_scope`). The hook scheme is part of the cross-analyser `gruff.hook.v1` contract, so any sibling port adopting hook mode must use the same `[ruleId, file, scope]` set and the same row-reconstruction bridge.

## Footgun: Frozen AnalysisConfig is not deeply immutable

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`AnalysisConfig` is a frozen dataclass, but its `rules` field is a mutable dictionary. Evidence anchors: `src/gruffpy/config/analysis_config.py` (search: `rules: dict[str, RuleSettings]`) and `src/gruffpy/config/analysis_config.py` (search: `def with_rule_settings`).

The non-obvious failure mode is that in-place mutation of `config.rules` can leak across contexts even though the object looks immutable. Use the `with_*` helpers or construct a fresh config when changing settings.

## Footgun: Compatibility CLI flags can be help-only

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

Some CLI flags exist for sibling-port surface compatibility before their runtime
plumbing exists. Evidence anchors: `src/gruffpy/cli_options.py` (search:
`expose_value=False`) and `src/gruffpy/cli.py` (search: `def _analysis_request`).

The non-obvious failure mode is that Click help can advertise a flag that is
accepted but discarded before `run_analysis()`. Before documenting a compatibility
flag as a workflow, prove the option value reaches the runtime request and add an
integration test for its side effect.

## Footgun: Removing a registered rule ID breaks downstream config loads

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

`ConfigLoader` rejects any `rules.<id>` entry whose key is not present in
`RuleRegistry.defaults()`. Evidence anchors: `src/gruffpy/config/loader.py`
(search: `Unknown rule id`) and `src/gruffpy/rule/catalog.py` (search:
`def _entry`).

The non-obvious failure mode is that dropping a previously-shipped rule from
the catalog turns every downstream config that pinned that rule into a hard
`ConfigError` at analyse/report time - the analyser fails before scanning
anything. An empirical reproduction with `test-quality.testdox-readability`
(removed in commit e8b8814) raises `ConfigError: Unknown rule id
"test-quality.testdox-readability"` when an upgraded project still mentions the
ID. Treat rule removals as a public-API break: either keep the ID as a
deprecated no-op for one release (accept-and-warn in the loader) or call the
removal out explicitly in release notes and the cross-implementation
compatibility contract.

## Footgun: minimumSeverity defaults span six surfaces in lockstep

**Status:** active | **Created:** 2026-05-26 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

When the family-wide `--fail-on` binary default for a gateable subcommand
moves, six source surfaces must move together: the deciding ADR
`.goat-flow/learning-loop/decisions/ADR-019-per-command-minimum-severity.md` (search:
`Per-Command`); the canonical defaults table in
`src/gruffpy/config/analysis_config.py` (search:
`MINIMUM_SEVERITY_BINARY_DEFAULTS`); the Click decorator default in
`src/gruffpy/cli_options.py` (search: `minimumSeverity.analyse in .gruff-py.yaml`); the validator
accept-set in `src/gruffpy/config/loader.py` (search:
`VALID_MINIMUM_SEVERITY_VALUES`); the init renderer in
`src/gruffpy/command/init_config.py` (search: `_render_minimum_severity_block`);
and the dashboard state factory in `src/gruffpy/cli_dashboard.py` (search:
`_resolve_config_dashboard_fail_on`). Two doc surfaces move alongside:
`docs/configuration.md` (search: `Severity Gate`) and `CHANGELOG.md`
(search: `minimumSeverity`).

The non-obvious failure mode is that moving the value in only one place
(e.g. flipping the Click decorator from `error` to `advisory`) without
updating the binary-defaults table or the init renderer produces silently
inconsistent behaviour: fresh `init` configs disagree with the CLI default,
and the dashboard form's seed value diverges from analyse runs. The
cross-port lockstep failure is the highest cost — every sibling
implementation must agree on the off-switch value (currently `none`, not
`never`); aliases are explicitly forbidden so divergence can't be papered
over.

Before changing any of these surfaces, grep the project for the OLD value
across all six source anchors above and confirm every site moves together.
ADR-019 records the contract; cross-port coordination posture lives in local
milestone planning notes (search: `Coordination posture`).

## Resolved Entries

## Footgun: OutputFormat accepted more formats than reporters implemented

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-15 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

Historical trap: `src/gruffpy/finding/output_format.py` listed `html`, `markdown`, `github`, `hotspot`, and `sarif`, and `src/gruffpy/cli.py` built Click choices from every enum value, but only JSON dispatched to a non-text reporter.

Resolved in M10: `src/gruffpy/cli.py` now dispatches every `OutputFormat` to a real reporter under `src/gruffpy/reporting/`, and `tests/integration/test_cli_smoke.py` plus `tests/unit/reporting/` prove HTML/report-filter behavior. Keep this entry because the broader lesson still applies: do not infer that an enum value has a schema, reporter, or tests until the dispatch and tests prove it.
