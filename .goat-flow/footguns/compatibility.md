---
category: compatibility
last_reviewed: 2026-05-24
---

## Footgun: Finding fingerprints depend on PHP-style JSON bytes

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

The fingerprint algorithm in `src/gruffpy/finding/fingerprint.py` is deliberately not plain `json.dumps(...).sha256()`. Evidence anchors: `src/gruffpy/finding/fingerprint.py` (search: `encoded = encoded.replace("/", r"\/")`) and `tests/unit/finding/test_fingerprint.py` (search: `PHP_GROUND_TRUTH`).

The non-obvious failure mode is that "simplifying" JSON encoding, changing slash escaping, expanding hashed fields, or reordering the payload breaks compatibility with gruff-php baselines while most local CLI output still appears normal. Any edit here must run `uv run pytest tests/unit/finding/test_fingerprint.py`.

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

## Resolved Entries

## Footgun: OutputFormat accepted more formats than reporters implemented

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-15 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

Historical trap: `src/gruffpy/finding/output_format.py` listed `html`, `markdown`, `github`, `hotspot`, and `sarif`, and `src/gruffpy/cli.py` built Click choices from every enum value, but only JSON dispatched to a non-text reporter.

Resolved in M10: `src/gruffpy/cli.py` now dispatches every `OutputFormat` to a real reporter under `src/gruffpy/reporting/`, and `tests/integration/test_cli_smoke.py` plus `tests/unit/reporting/` prove HTML/report-filter behavior. Keep this entry because the broader lesson still applies: do not infer that an enum value has a schema, reporter, or tests until the dispatch and tests prove it.
