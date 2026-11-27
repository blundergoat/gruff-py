---
category: compatibility
last_reviewed: 2026-11-23
---

## Footgun: Hotspot and config schema strings are per-port while analysis, summary, and baseline strings are shared

**Status:** active | **Created:** 2026-08-11 | **Updated:** 2026-11-23 | **Evidence:** OBSERVED
**Decision changed:** Treat `gruff.analysis.v3`, `gruff.summary.v3`, and `gruff.baseline.v3` as the shared contract and `gruff-py.hotspot.v1` and `gruff-py.config.v0.1` as per-port strings; grep the sibling checkouts before changing or "restoring" any of them.
**Trigger phase:** READ
**Tags:** hallucination-risk: high

**Prevention:** Before changing a schema string, grep each sibling checkout for its current constant instead of trusting local prose, this entry included. Change a shared string only through the workspace `FAMILY-CONTRACT.md`. A per-port string can change alone, but no sibling reader parses it.

`src/gruffpy/analysis/schema.py` (search: `BASELINE_SCHEMA_VERSION = "gruff.baseline.v3"`) emits the shared `gruff.analysis.v3`, `gruff.summary.v3`, and `gruff.baseline.v3`. gruff-go, gruff-php, gruff-rs, and gruff-ts emitted the same three strings when checked on 2026-11-23. The same module keeps two per-port strings, `gruff-py.hotspot.v1` and `gruff-py.config.v0.1`; gruff-ts names its config schema the same way (`gruff-ts.config.v0.1`).

Hotspot output is where the ports still diverge. On 2026-11-23 gruff-rs and gruff-ts emitted `gruff.hotspot.v1`, gruff-php emitted `gruff-php.hotspot.v1`, and gruff-go had no hotspot schema. The family contract ratifies no shared hotspot schema, and hotspot output has no read path or fallback, so no consumer can parse every port's hotspot report by schema string. Sibling paths stay out of backticks because the learning-loop ref checker resolves them from this project root.

The baseline string used to be the trap. Before 0.6.0, gruff-py wrote `gruff-py.baseline.v1` and read `gruff.baseline.v1` as a fallback. `src/gruffpy/analysis/baseline.py` (search: `LEGACY_BASELINE_SCHEMA_VERSIONS`) now refuses both v1 forms and points the user to `gruff-py analyse --migrate-baseline`. Prose that names a prefixed baseline string as current output is stale.

## Footgun: Finding fingerprints depend on PHP-style JSON bytes

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

The fingerprint algorithm in `src/gruffpy/finding/fingerprint.py` is deliberately not plain `json.dumps(...).sha256()`. Evidence anchors: `src/gruffpy/finding/fingerprint.py` (search: `encoded = encoded.replace("/", r"\/")`) and `tests/unit/finding/test_fingerprint.py` (search: `PHP_GROUND_TRUTH`).

The non-obvious failure mode is that "simplifying" JSON encoding, changing slash escaping, expanding hashed fields, or reordering the payload breaks compatibility with gruff-php baselines while most local CLI output still appears normal. Any edit here must run `uv run pytest tests/unit/finding/test_fingerprint.py`.

## Footgun: hook and analysis `stableIdentity` use different input sets for symbol-less file/project findings

**Status:** active | **Created:** 2026-06-09 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Never compare a hook `stableIdentity` with an analysis `stableIdentity`; carry reviewed findings into hook mode only through a ratified `gruff.baseline.v3` file.

Two identity schemes share the field name `stableIdentity` but diverge. The analysis/report identity, `src/gruffpy/finding/fingerprint.py` (search: `def stable_identity_for`), hashes `[ruleId, file, message]` whenever `symbol is None` (ADR-020). The `gruff.hook.v2` identity, `src/gruffpy/hook_contract.py` (search: `def _hook_stable_identity`), instead hashes `[ruleId, file, scope]` for `file`/`project` scope and only falls back to `message` for `line` scope. So one `size.file-length` finding gets a message-keyed digest in `analyse --format json` and a scope-keyed digest in hook mode.

The original incident (2026-06-09): feeding an `analyse --format json` report to `gruff-py hook --baseline` re-surfaced file/project findings (`size.file-length`, `docs.missing-module-docstring`, `docs.todo-density`, ...) because the analysis digest never matched the hook digest. A row-reconstruction bridge in the hook reader patched that at the time. That bridge is gone: `src/gruffpy/cli_hook.py` (search: `def _apply_hook_baseline`) now applies only the ratified baseline v3 file that `analyse --generate-baseline` writes, matched by the shared baseline code, and refuses any other schema. `tests/integration/test_hook_contract.py` (search: `test_hook_baseline_refuses_a_document_that_is_not_a_v3_baseline`) proves an analysis report is rejected. Do not restore the bridge to make analysis JSON acceptable again; the divergence itself remains, so any new consumer that joins hook output with analysis output by `stableIdentity` will miss file- and project-scope findings.

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

## Footgun: minimumSeverity defaults span six surfaces in lockstep

**Status:** active | **Created:** 2026-05-26 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

When the family-wide `--fail-on` binary default for a gateable subcommand
moves, six source surfaces must move together: the deciding ADR
`.goat-flow/learning-loop/decisions/ADR-019-per-command-minimum-severity.md` (search:
`Per-Command`); the canonical defaults table in
`src/gruffpy/config/analysis_config.py` (search:
`MINIMUM_SEVERITY_BINARY_DEFAULTS`); the Click decorator default in
`src/gruffpy/cli_options.py` (search: `failOn.analyse in .gruff-py.yaml`); the validator
accept-set in `src/gruffpy/config/loader.py` (search:
`VALID_MINIMUM_SEVERITY_VALUES`); the init renderer in
`src/gruffpy/command/init_config.py` (search: `_default_init_analysis_config`);
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

## Footgun: Removing a registered rule ID breaks downstream config loads

**Status:** resolved | **Created:** 2026-05-24 | **Resolved:** 2026-06-13 | **Evidence:** ACTUAL_MEASURED

Resolved in `0490c9f`: an unknown `rules.<id>` entry now warns and is ignored
by default, and raises `ConfigError` only under `--strict-config`.
`src/gruffpy/config/loader.py` (search: `Unknown rule id`) routes the entry
through `_warn_or_raise`, and
`tests/unit/config/test_loader_precedence.py` (search: `def test_removed_npath_rule_pin_warns_by_default_and_raises_under_strict`)
pins both modes. Rule removals still belong in release notes, because
strict-config users get the hard error.

Before that change, `ConfigLoader` rejected any `rules.<id>` entry whose key
was not present in `RuleRegistry.defaults()` (`src/gruffpy/rule/catalog.py`,
search: `def _entry`). Dropping a previously shipped rule turned every
downstream config that pinned it into a hard `ConfigError` before scanning. An
empirical reproduction with `test-quality.testdox-readability` (removed in
commit e8b8814) raised `ConfigError: Unknown rule id
"test-quality.testdox-readability"` when an upgraded project still mentioned
the ID.

## Footgun: OutputFormat accepted more formats than reporters implemented

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-15 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

Historical trap: `src/gruffpy/finding/output_format.py` listed `html`, `markdown`, `github`, `hotspot`, and `sarif`, and `src/gruffpy/cli.py` built Click choices from every enum value, but only JSON dispatched to a non-text reporter.

Resolved in M10: `src/gruffpy/cli.py` now dispatches every `OutputFormat` to a real reporter under `src/gruffpy/reporting/`, and `tests/integration/test_cli_smoke.py` plus `tests/unit/reporting/` prove HTML/report-filter behavior. Keep this entry because the broader lesson still applies: do not infer that an enum value has a schema, reporter, or tests until the dispatch and tests prove it.
