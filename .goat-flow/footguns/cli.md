---
category: cli
last_reviewed: 2026-05-24
---

## Footgun: Optional-value Click options consume the next positional argument

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

`_optional_path_option` builds Click options with `is_flag=False, flag_value=...`
so a bare `--baseline` falls back to `DEFAULT_BASELINE_FILENAME`. Evidence
anchors: `src/gruffpy/cli_options.py` (search: `def _optional_path_option`) and
`src/gruffpy/cli_options.py` (search: `"--generate-baseline"`).

The non-obvious failure mode is that the analyse command takes a variadic
`paths` argument, so `gruff-py analyse --baseline src` is parsed as
`paths=(), baseline_path="src"` and silently scans `.` instead of `src/`. A
`CliRunner` reproduction confirms this against the current `_optional_path_option`
shape; the next token is always consumed by the option even when the user meant
it as a positional path. Before adding another optional-value option, verify
that no variadic positional follows it, or switch to a pure flag plus a
separate `--*-path` argument and add an integration test for the
`option-then-path` shape.

## Footgun: Interactive init prompt corrupts structured stdout

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

`_maybe_prompt_to_init_config` runs unconditionally for analyse, report, and
summary when stdin is a TTY and no config source is discovered. Evidence
anchors: `src/gruffpy/cli.py` (search: `_maybe_prompt_to_init_config(request`)
and `src/gruffpy/cli.py` (search: `def _maybe_prompt_to_init_config`).

The non-obvious failure mode is that the prompt and the `_init_success_message`
both write to stdout via `click.confirm` and `click.echo`. When the user runs
`gruff-py analyse --format json` (or `report --format sarif`, or `summary
--format json`) interactively and accepts, the human-readable text is
prepended to the structured payload and breaks downstream parsers. The prompt
also fires regardless of `--quiet`/`--silent` because it only consults
`is_interaction_disabled` and TTY state, not `should_suppress_output`. Gate the
prompt on a text-shaped output format and on `_state().should_suppress_output`
before calling `click.confirm`, and route any success message to stderr when the
command's primary output is structured.
