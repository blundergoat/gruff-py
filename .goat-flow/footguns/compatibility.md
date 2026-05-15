---
category: compatibility
last_reviewed: 2026-05-13
---

## Footgun: Finding fingerprints depend on PHP-style JSON bytes

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

The fingerprint algorithm in `src/gruff/finding/fingerprint.py` is deliberately not plain `json.dumps(...).sha256()`. Evidence anchors: `src/gruff/finding/fingerprint.py` (search: `encoded = encoded.replace("/", r"\/")`) and `tests/unit/finding/test_fingerprint.py` (search: `PHP_GROUND_TRUTH`).

The non-obvious failure mode is that "simplifying" JSON encoding, changing slash escaping, expanding hashed fields, or reordering the payload breaks compatibility with gruff-php baselines while most local CLI output still appears normal. Any edit here must run `uv run pytest tests/unit/finding/test_fingerprint.py`.

## Footgun: OutputFormat accepted more formats than reporters implemented

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-15 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

Historical trap: `src/gruff/finding/output_format.py` listed `html`, `markdown`, `github`, `hotspot`, and `sarif`, and `src/gruff/cli.py` built Click choices from every enum value, but only JSON dispatched to a non-text reporter.

Resolved in M10: `src/gruff/cli.py` now dispatches every `OutputFormat` to a real reporter under `src/gruff/reporting/`, and `tests/integration/test_cli_smoke.py` plus `tests/unit/reporting/` prove HTML/report-filter behavior. Keep this entry because the broader lesson still applies: do not infer that an enum value has a schema, reporter, or tests until the dispatch and tests prove it.

## Footgun: Frozen AnalysisConfig is not deeply immutable

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`AnalysisConfig` is a frozen dataclass, but its `rules` field is a mutable dictionary. Evidence anchors: `src/gruff/config/analysis_config.py` (search: `rules: dict[str, RuleSettings]`) and `src/gruff/config/analysis_config.py` (search: `def with_rule_settings`).

The non-obvious failure mode is that in-place mutation of `config.rules` can leak across contexts even though the object looks immutable. Use the `with_*` helpers or construct a fresh config when changing settings.
