---
category: cli
last_reviewed: 2026-11-26
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

The trap recurred on 2026-11-22 in PR #10. On a temporary copy, `gruff-py
analyse --generate-baseline target.py` replaced the Python operand with JSON.
`_AnalyseCommand.parse_args` in `src/gruffpy/cli_options.py` now supplies the
conventional destination for the bare flag before Click consumes operands.
`--generate-baseline=PATH` supplies a custom destination in the same token.
The two forms are covered in `tests/integration/test_cli_smoke.py`.

That fix went too far: on 2026-11-26 the gruff-spec `cli` and `hook` suites
failed because `--generate-baseline reviewed-baseline.json`, the family
spelling, scanned the JSON name as a path and exited 2. A next word ending in
`.json` is now read as the destination; any other word stays a scan target
(`tests/integration/test_cli_smoke.py`, search:
`test_cli_baseline_flag_writes_the_json_file_named_next`).

## Footgun: A rejected source path can break its own JSON diagnostic

**Status:** active | **Created:** 2026-11-22 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Keep path resolution out of later scan steps once discovery rejects an operand, and omit unpublishable diagnostic locations.

Running `analyse --format json loop.py` on a self-referencing `loop.py` symlink exited 1 with no output. Discovery rejected the operand, then the scan scope calculation tried to resolve it again. Treat such a scan as partial and let the JSON report carry the diagnostic even when the missing input has no project-relative location.

The runner makes the scope decision in `src/gruffpy/analysis/runner.py` (search: `def run_analysis`). The JSON writer uses the same permissive path projection for missing inputs as for requested inputs in `src/gruffpy/analysis/machine_contract.py` (search: `def analysis_payload`). The reproduction is in `tests/integration/test_cli_smoke.py` (search: `def test_cli_reports_a_symlink_loop_as_a_fatal_json_diagnostic`).

## Resolved Entries

## Footgun: cli.py routinely sits within 20 lines of the file-length error threshold

**Status:** resolved | **Created:** 2026-05-26 | **Resolved:** 2026-11-23 | **Evidence:** ACTUAL_MEASURED

Resolved by measurement on 2026-11-23. `size.file-length` has counted
substantive lines since `767a736` (2026-08-05), so docstrings, comments, and
blank lines no longer count. `src/gruffpy/cli.py` measured 839 against the
1000-line default and the dogfood self-check reported no findings, while
`wc -l` reported 1535 for the same file. A physical line count is no longer
the measurement. If cli.py nears the threshold again, reopen this entry and
measure with the rule's own counter:
`uv run python -c "import ast,pathlib; from gruffpy.rule.size.file_length_rule import _substantive_line_count; s=pathlib.Path('src/gruffpy/cli.py').read_text(); print(_substantive_line_count(s, ast.parse(s)))"`

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

The trap recurred on 2026-07-16: a three-line dashboard port-ordering guard
made the 999-line file 1002 lines. Ruff, formatting, mypy, focused tests, the
full 3,080-test suite, and package build all passed; only the required dogfood
scan emitted `size.file-length`. Keeping the guard while removing two
non-semantic lines in the same validation area returned the file to the exact
1,000-line ceiling.

While the rule counted physical lines, the prevention was to check the line
count before adding code to cli.py and, within 20 lines of 1000, to extract
the new code to a subcommand module first. Ruff, mypy, and pytest all passed
while the dogfood scan slipped into exit code 1.

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
