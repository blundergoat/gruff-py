---
category: cli
last_reviewed: 2026-05-26
---

## Footgun: Click optional-value options + variadic positionals stay tempting

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

The underlying Click pattern - declaring an option with `is_flag=False,
flag_value="..."` so a bare `--option` falls back to a default value - is
unambiguous on its own, but combines disastrously with a variadic positional
argument: the next token is always consumed by the option even when the user
meant it as a positional. The 0.1.1 occurrence used `_optional_path_option`
for `--baseline` and `--generate-baseline` and was reproduced empirically with
`CliRunner` before being removed. Evidence anchors:
`src/gruffpy/cli_options.py` (search: `def _path_option`) shows the replacement
helper and `tests/integration/test_cli_smoke.py`
(search: `test_cli_analyse_baseline_option_conflicts_are_diagnostics`) covers
the new mutex contract.

Before adding any new Click option with optional value semantics (`is_flag=False,
flag_value=...`), check whether the command takes a variadic positional. If it
does, prefer splitting into a pure boolean flag plus a separately-named
required-value option (e.g. `--foo` flag + `--foo-path PATH`) and add a
`CliRunner` test that exercises the `--option-then-positional` shape.

## Footgun: cli.py routinely sits within 20 lines of the file-length error threshold

**Status:** active | **Created:** 2026-05-26 | **Evidence:** ACTUAL_MEASURED

`src/gruffpy/cli.py` (search: `class CliGroup`) is the project's Click entry
point and concentrates: the root command group, every subcommand handler
(`analyse`, `dashboard`, `init`, `list-rules`, `report`, `summary`,
`metric-calibration`, `completion`, `help`), the analyse/dashboard request
dataclasses, and a stack of internal helpers (`_analysis_request`,
`_run_analysis_for_cli`, `_maybe_prompt_to_init_config`, `_render_report`,
`_summary_payload`, `_summary_text`, etc.). Even small additive features tend
to land 10-20 lines of code here, which keeps the file within striking
distance of the `size.file-length` error threshold (currently 1000 — see
`src/gruffpy/rule/size/file_length_rule.py`).

Empirical evidence from 0.1.2: the M02 wave (CLI precedence helper +
`_AnalysisCliRequest` fields + per-command precedence wiring) pushed cli.py
to **1008 lines** and required extracting the helper into `cli_options.py`
to land under the threshold. The M03 wave (dashboard initial-state factory
+ `_resolve_config_dashboard_fail_on`) pushed cli.py to **1046 lines** and
required extracting both helpers and the dashboard request dataclass into a
new `src/gruffpy/cli_dashboard.py` module. The dogfood scan caught both
regressions before commit.

Before adding any new function or dataclass to cli.py, check `wc -l
src/gruffpy/cli.py` first. If it is within 20 lines of 1000, extract the
new code to a sibling module before writing it (the natural seams are by
subcommand — `cli_dashboard.py` already exists; `cli_summary.py`,
`cli_init.py`, etc. are reasonable next splits). Adding code first and
"figuring out the threshold later" is the trap that fires every time:
ruff/mypy/pytest all pass while the dogfood quietly slips into
exit-code-1 territory. The footgun resolves itself once cli.py drops well
below 1000 lines via dedicated subcommand modules; until then, every
contributor must spot-check before merging.

## Resolved Entries

## Footgun: Optional-value `--baseline` / `--generate-baseline` consumed the next path

**Status:** resolved | **Created:** 2026-05-24 | **Resolved:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

Historical trap: `_optional_path_option` declared `--baseline` and
`--generate-baseline` with `is_flag=False, flag_value=DEFAULT_BASELINE_FILENAME`,
so `gruff-py analyse --baseline src` was parsed as
`paths=(), baseline_path="src"` and silently scanned `.` instead of `src/`. A
`CliRunner` reproduction in the same session printed
`"paths=() baseline_path='src'"` to confirm before the fix.

Resolved on 2026-05-24 by splitting both options into a pure boolean flag plus
a required-value path option: `--baseline-path PATH`, `--generate-baseline`
(flag, writes to `gruff-baseline.json`), and `--generate-baseline-path PATH`.
The helper `_optional_path_option` was replaced with `_path_option`
(`src/gruffpy/cli_options.py`, search: `def _path_option`). The active footgun
above keeps the broader trap (Click optional-value + variadic positional)
discoverable for future option work.

## Footgun: Interactive init prompt corrupted structured stdout

**Status:** resolved | **Created:** 2026-05-24 | **Resolved:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

Historical trap: `_maybe_prompt_to_init_config` wrote the `click.confirm`
prompt and the `_init_success_message` to stdout. When a user accepted the
prompt during `gruff-py analyse --format json` (or `report --format sarif`,
or `summary --format json`), the human-readable text was prepended to the
structured payload and broke downstream parsers. The prompt also fired
regardless of `--quiet`/`--silent` because it only consulted
`is_interaction_disabled` and TTY state.

Resolved on 2026-05-24 in `src/gruffpy/cli.py`
(search: `def _maybe_prompt_to_init_config`): the function now short-circuits
on `_state().should_suppress_output`, passes `err=True` to both `click.confirm`
and the success `click.echo`, and accepts an explicit `project_root` parameter
so dashboard callers point the prompt at the scanned project rather than
`Path.cwd()`.
