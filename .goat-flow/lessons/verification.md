---
category: verification
last_reviewed: 2026-05-20
---

## Lesson: Run targeted formatting before broad verification on dirty surfaces

**Created:** 2026-05-18
**Incident:** During M25, `uv run ruff format --check src tests` mixed a new
touched-file formatting issue with pre-existing unrelated formatting drift
outside the patch. The correction was to run `uv run ruff format` only on the
M25-touched files, then keep the repo-wide format check marked as blocked by
unrelated drift.

When a repo-wide non-mutating format check is already known to fail, run a
touched-file format check or formatter pass before the broad gate so the
agent-owned formatting state is separated from unrelated workspace drift.

## Lesson: Re-run raw-source analyzers after formatting fixture strings

**Created:** 2026-05-18
**Incident:** While removing `docs.todo-density` findings from
`src/gruffpy/rule/sensitive_data/hardcoded_env_value_rule.py`,
`tests/unit/rule/docs/test_todo_density_rule.py`,
`tests/unit/rule/docs/test_docs_pillar_integration.py`, and
`tests/unit/rule/waste/test_commented_out_code_rule.py`, adjacent string
literal splits were formatted back into raw marker tokens. The focused tests
still passed, but `uv run gruff-py analyse src/ --format json --fail-on none`
and `uv run gruff-py analyse . --format json --fail-on none` still reported
`docs.todo-density`.

When a rule scans raw source text and tests need runtime strings containing
trigger tokens, use a construction that the formatter will not fold back into
the raw token, such as `"".join(("TO", "DO"))`, and re-run the analyzer after
formatting rather than trusting the unit test alone.

## Lesson: Test directive parsers against reason delimiters before dogfood

**Created:** 2026-05-20
**Incident:** During M24, the first `docs.ignore-directive-reason` tests showed
that `src/gruffpy/rule/docs/ignore_directive_reason_rule.py` initially let the
`noqa` directive regex consume `- re-exported public API` as part of the
directive, while `type: ignore[attr-defined]` stopped before the bracketed
code. Focused tests caught the bug before the rule was registered for dogfood.

When implementing source-comment directive parsers, test each supported
directive with no reason, `-` / `--` reasons, second-`#` reasons, and bracketed
payloads before broad dogfood. The regex should stop at the reason delimiter,
not include the rationale in the directive payload.
