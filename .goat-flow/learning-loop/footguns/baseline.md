---
category: baseline
last_reviewed: 2026-05-24
---

## Footgun: run_analysis(baseline=None) auto-applies the default baseline file

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

`run_analysis` defaults `baseline` to `None`, which the runner substitutes with
`BaselineOptions()` (apply_path=None, generate_path=None, disabled=False).
Evidence anchors: `src/gruffpy/analysis/analysis_run_request.py`
(search: `baseline: BaselineOptions | None = None`),
`src/gruffpy/analysis/runner.py`
(search: `baseline_options = request.baseline if request.baseline is not None else BaselineOptions()`),
`src/gruffpy/analysis/runner.py` (search: `def _apply_baseline_if_present`), and
`src/gruffpy/analysis/runner.py` (search: `def _resolve_baseline_selection`).

The non-obvious failure mode is that "no baseline argument" does NOT mean "no
baseline applied" - the resolver looks for `gruff-baseline.json` in the project
root and silently suppresses every matching finding with `source="default"`. An
empirical reproduction (run analysis, write baseline, re-run without `baseline=`)
shows 4 findings collapse to 0 with `suppressed_findings=4`. Any caller that
does not want this behaviour must pass `baseline=BaselineOptions(disabled=True)`
explicitly; the dashboard pathway in `src/gruffpy/command/dashboard_server.py`
(search: `baseline=BaselineOptions(disabled=True)`) is the current reference
example. New `run_analysis` callers should choose explicitly between
auto-apply, explicit baseline, or disabled; do not rely on the default.

## Resolved Entries

## Footgun: apply_baseline reported stale-evaluation as "full-project" regardless of scan scope

**Status:** resolved | **Created:** 2026-05-24 | **Resolved:** 2026-05-24 | **Evidence:** OBSERVED

Historical trap: `apply_baseline` flagged every unmatched baseline entry as
stale and labelled the report with `stale_evaluation="full-project"` even when
the caller passed a narrowed paths tuple such as `("src/pkg",)`. A developer
who ran `gruff-py analyse src/pkg` and regenerated the baseline based on the
reported stale entries would drop suppressions for findings outside the
scanned subtree, re-surfacing legitimate debt on the next full scan.

Resolved on 2026-05-24 by adding a `scan_scope` parameter to `apply_baseline`
(`src/gruffpy/analysis/baseline.py`, search: `def apply_baseline`). The runner
derives the scope via `_scan_scope(paths, project_root)`
(`src/gruffpy/analysis/runner.py`, search: `def _scan_scope`) and passes
`"partial-scope"` whenever `paths` is narrower than `(".",)`. Partial scans
skip the stale-entry calculation entirely; the report still reports
`stale_evaluation` so downstream tooling can distinguish a vacuously-empty
stale list from a full-project audit. Since 2026-06-10 (PR #6 review), paths
are resolved against the project root first, so `./` and absolute-root
spellings count as full-project rather than skipping stale evaluation.
