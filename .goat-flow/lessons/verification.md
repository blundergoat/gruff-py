---
category: verification
last_reviewed: 2026-05-24
---

## Lesson: Read the rule body before calling a rule dead or leftover

**Created:** 2026-05-22
**Incident:** While scoping security-scan improvements, the agent claimed
`src/gruffpy/rule/security/extract_compact_user_input_rule.py` and
`src/gruffpy/rule/security/variable_import_rule.py` "look like PHP-port
leftovers" based solely on the PHP-flavoured rule IDs
(`security.extract-compact-user-input`, `security.variable-import`). Reading
the files showed both target real Python risks - `f(**request.json)` kwargs
splat across Flask/Django/FastAPI, and `importlib.import_module(non_literal)`
/ `__import__(non_literal)`. Tests pass (`8 passed`) and both rules pull
weight. The agent had to retract the hypothesis to the user.

When a rule ID's lineage suggests it might not apply to this language, the
ID is not evidence - read the `analyse` method and tests before stating
"looks like a leftover" or "probably dead". This is a CLAUDE.md
hallucination red-flag #4 ("looks like", "probably") applied to dead-code
hypotheses, not just verification claims.

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

## Lesson: Rule removals must update dogfood config before full pytest

**Created:** 2026-05-20
**Incident:** Removing `docs.todo-actionability` from
`src/gruffpy/rule/catalog.py`, generated `docs/rules.md`, and docs-pillar tests
left `.gruff-py.yaml` with the stale rule in both `selection.rules` and
`rules:`. Focused rule/docs tests passed, but full `uv run pytest` failed
`tests/unit/config/test_gruff_py_yaml_registry_coverage.py` because the dogfood
config must mirror `RuleRegistry.defaults()`.

When adding or removing a built-in rule, grep and update `.gruff-py.yaml`
alongside the catalog, generated docs, fixtures, and focused rule tests before
running broad verification.

## Lesson: Inspect each item's body before bucketing tests for bulk deletion

**Created:** 2026-05-24
**Incident:** During a test-suite audit, the agent grepped for `def test_definition` across `tests/unit/rule/**/test_*_rule.py`, got 32 matches, and recommended deleting all 32 as "trivial duplicates of catalog membership tests". When the user authorised the deletion, the agent paused to read each body before deleting and discovered the group split cleanly into:

- 17 plain `assert d.id == "<literal>"` (truly trivial, redundant with `tests/unit/rule/test_catalog.py::test_no_concrete_rule_class_is_omitted_from_catalog`).
- 15 `test_definition_uses_default_thresholds` variants that pinned non-trivial default threshold values — e.g. `tests/unit/rule/size/test_class_length_rule.py` pinned `{"warning": 1000, "error": 1000}` and `tests/unit/rule/complexity/test_npath_complexity_rule.py` pinned `{"warning": 200, "error": 500}`. Those 15 were the only tests pinning the public default thresholds; silently deleting them would have removed the drift guard.

The agent had to interrupt the bulk delete and ask the user which bucket they meant, instead of charging ahead with a 32-test wipe that the recommendation had already framed as homogeneous.

When proposing a bulk action (delete, rename, refactor) over a group identified by a `grep` of name patterns, read each matched body before recommending the action - the matching name is a proxy for "items are equivalent", and only the body proves it. This is the same family as the dead-code lesson (`feedback_read_before_dead_code_claims`) and the runtime-vs-grep lesson above: a name pattern, a count, and a directory listing are all proxies; the artefact's body is the contract.

## Lesson: Reproduce Click option-parsing claims with CliRunner before reasoning about them

**Created:** 2026-05-24
**Incident:** While triaging PR review feedback that flagged `gruff-py analyse
--baseline src` as ambiguous, the agent first reasoned about Click's
`is_flag=False, flag_value=...` semantics and concluded the bot was right.
The reasoning was correct, but in a parallel session the agent had to
double-check whether removing one helper would break the `--baseline-then-path`
case for any other call site. The actual proof came from a few lines of
`CliRunner`:

```
argv=['--baseline', 'src']          -> "paths=() baseline_path='src'"
argv=['--baseline', 'src', 'tests'] -> "paths=('tests',) baseline_path='src'"
```

That same six-line reproduction also verified the fix
(`['--baseline-path', 'baseline.json', 'src']` keeps `src` as a positional) and
caught a regression test that needed updating, all in under a minute.

When a review (bot or human) makes a CLI behaviour claim - "this option
consumes the next argument", "this flag corrupts JSON stdout", "this combo
returns the wrong exit code" - drive the verification with `click.testing.CliRunner`
before debating Click's grammar. The matrix runs in seconds, the result is
unambiguous, and the same harness is reusable as a regression test.

## Lesson: Count registered rules from the runtime registry, not by grepping `_entry(`

**Created:** 2026-05-24
**Incident:** While double-checking PR review feedback that flagged a
README/`docs/rules.md` rule-count mismatch, the agent ran
`grep -c "_entry(" src/gruffpy/rule/catalog.py`, got `117`, and concluded the
README (which says 117) was right and `docs/rules.md` (which says 116) was the
stale one. Running `RuleRegistry.defaults().all()` then reported only 116
registered rules. The 117th grep hit was the function definition
`def _entry(factory: RuleFactory)` at the top of the file, not a rule
registration. The agent had to retract the verdict to the user.

When verifying catalog/registry counts, drive from the actual runtime state -
`uv run python -c "from gruffpy.rule.registry import RuleRegistry; print(len(list(RuleRegistry.defaults().all())))"` -
not from raw `grep` of a constructor name, because the function or class
*definition* will also match. Anchored grep such as `^    _entry(` works too,
but the registry-driven check is the source of truth and survives any
catalog-layout refactor.

## Lesson: Static rule catalog scans must exclude support protocols

**Created:** 2026-05-20
**Incident:** While replacing a dynamic `importlib.import_module()` scan in
`tests/unit/rule/test_catalog.py`, the first static `*_rule.py` source scan
included `src/gruffpy/rule/project_rule.py` and reported
`ProjectRuleProtocol` as an omitted concrete rule. Focused verification caught
the false positive before broader checks.

When converting dynamic rule discovery to source scanning, explicitly exclude
support contract modules such as `project_rule.py` and keep the predicate tied
to concrete rule implementation files, not just filename suffixes.
