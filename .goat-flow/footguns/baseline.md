---
category: baseline
last_reviewed: 2026-05-24
---

## Footgun: run_analysis(baseline=None) auto-applies the default baseline file

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

`run_analysis` defaults `baseline` to `None`, which `_handle_baseline`
substitutes with `BaselineOptions()` (apply_path=None, generate_path=None,
disabled=False). Evidence anchors: `src/gruffpy/analysis/runner.py`
(search: `baseline: BaselineOptions | None = None`),
`src/gruffpy/analysis/runner.py` (search: `def _apply_baseline_if_present`), and
`src/gruffpy/analysis/runner.py` (search: `def _resolve_baseline_selection`).

The non-obvious failure mode is that "no baseline argument" does NOT mean "no
baseline applied" - the resolver looks for `gruff-baseline.json` in the project
root and silently suppresses every matching finding with `source="default"`.
An empirical reproduction (run analysis, write baseline, re-run without
`baseline=`) shows 4 findings collapse to 0 with `suppressed_findings=4`.
`command/dashboard_server.py` (search: `report = run_analysis`) currently calls
the pipeline without any baseline argument, and its compat
`--no-baseline`/`--baseline` flags at `src/gruffpy/cli_options.py`
(search: `_DASHBOARD_COMMAND_DECORATORS`) are `expose_value=False`, so dashboard
users cannot opt out. Any caller that does not want this behaviour must pass
`baseline=BaselineOptions(disabled=True)` explicitly.

## Footgun: apply_baseline reports stale-evaluation as "full-project" regardless of scan scope

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`apply_baseline` flags every unmatched baseline entry as stale and labels the
report with `stale_evaluation="full-project"` even when the caller passed a
narrowed paths tuple such as `("src/pkg",)`. Evidence anchors:
`src/gruffpy/analysis/baseline.py` (search: `stale_evaluation="full-project"`)
and `src/gruffpy/analysis/baseline.py` (search: `def apply_baseline`).

The non-obvious failure mode is that a developer who runs `gruff-py analyse
src/pkg` and then regenerates the baseline based on the reported stale entries
will drop suppressions for findings outside that subtree. The next full scan
re-surfaces those findings as new debt even though they were legitimate
baseline entries the whole time. Until the stale calculation knows the scan
scope, treat the `stale` list as authoritative only for full-tree analyse runs
and either pass scope information into `apply_baseline` or skip the stale
metadata when paths is anything narrower than the project root.
