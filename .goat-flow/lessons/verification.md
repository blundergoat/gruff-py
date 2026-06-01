---
category: verification
last_reviewed: 2026-06-02
---

## Lesson: Verify changed-region hunk tests against real finding spans

**Created:** 2026-06-02
**Incident:** During M04 hook-native changed-code gate testing, the agent first
expected `--changed-scope hunk` to exclude a missing-function-docstring finding
when only the function body changed. The focused test failed because
`src/gruffpy/rule/docs/missing_function_docstring_rule.py`
(search: `end_line=node.end_lineno`) reports the finding across the whole
function span, and `src/gruffpy/analysis/changed_region.py`
(search: `def _is_finding_location_changed`) correctly treats any overlap
between `line`-`end_line` and the changed hunk as in-scope. The fix was to use
a single-line security call finding outside the edited hunk but inside the
changed function for the symbol-vs-hunk regression.

When testing changed-region hunk behaviour, read the rule's `Finding` location
shape first. Do not assume hunk filtering uses only the primary line; it uses
the full reported location span when `end_line` is present.

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

**Updated:** 2026-06-02. During the sensitive-data rule expansion, focused rule
and reporter tests passed, but `uv run gruff-py analyse src tests --format json
--fail-on none --no-baseline` reported new sensitive-data findings from raw
Google API-key suffixes, service-account examples, URL credentials, and email-
shaped placeholders embedded in test/doc fixtures. The correction was to split
synthetic fixture strings at source level and tighten the GCP detector so its
own docstring did not satisfy the marker co-occurrence rule.

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

## Lesson: Re-run the dogfood gate after adding branches, even when the change "feels small"

**Created:** 2026-05-25
**Incident:** While fixing a config-loader bug (Codex PR #3 review), the agent
added two `if "<key>" in allowlists:` guards inside `_apply_allowlists` to stop
silently clobbering seeded defaults. The functional change was trivial - two
membership checks - but the self-check `uv run gruff-py analyse src tests
--fail-on advisory` then surfaced a new `error`-severity finding:
`complexity.npath` reporting NPATH 972 (>500 error threshold) on
`ConfigLoader._apply_allowlists`. Evidence anchors: `src/gruffpy/config/loader.py`
(search: `_validate_string_list_allowlists`) shows the helper split that brought
NPATH back below 500. The `complexity.npath` rule was later removed in the
0.3.0 plan, but the verification lesson still applies: the fix was to extract
two helpers (`_validate_string_list_allowlists` and `_apply_present_allowlists`)
so each function's branch count stayed local.

When extending any function that already had multiple `if` guards or `or`/`and`
short-circuits, run `uv run gruff-py analyse <changed-file> --fail-on advisory`
before claiming the change is low-impact - NPATH multiplies branches, so each
new `if` can push a function past the project's own complexity gate. Prefer
extracting a per-key helper over chaining additional conditionals at the same
nesting level.

## Lesson: Suppression directives need a `--` rationale suffix or docs.ignore-directive-reason fires

**Created:** 2026-05-25
**Incident:** After clearing ten test-quality advisories with inline
`# gruff: disable-file=<rule-id>` / `disable-next=<rule-id>` directives in
`tests/integration/test_cli_smoke.py` and `tests/unit/reporting/test_reporters.py`,
the next `uv run gruff-py analyse src tests --fail-on advisory` run reported
three `warning`-severity findings from `docs.ignore-directive-reason` complaining
that suppression directives were "used without a reason." Evidence anchors:
`src/gruffpy/rule/docs/ignore_directive_reason_rule.py` (search: `class IgnoreDirectiveReasonRule`)
shows the rule body and `docs/rules.md` (search: `## Suppressing Findings`)
documents the `--` / `-` / second-`#` reason delimiters the rule expects.

When adding any `# gruff: disable...` directive, always append a short
rationale after `--` on the same comment, e.g. `# gruff: disable-file=test-quality.eager-test -- smoke tests assert many invariants per call.`
The dogfood gate ships this rule by default, so suppressions without rationale
look "clean" locally but fail CI's `--fail-on advisory` step. This applies
symmetrically to `disable`, `disable-next`, and `disable-file`.

## Lesson: Quote YAML boolean-like strings in dogfood option defaults

**Created:** 2026-05-31
**Incident:** While adding the `naming.boolean-prefix` `acceptedBooleanNames`
option, `.gruff-py.yaml` initially listed `yes` unquoted. PyYAML parsed it as
the boolean `True`, so `tests/unit/config/test_gruff_py_yaml_registry_coverage.py`
(search: `test_repo_yaml_options_match_definition_defaults`) failed even
though `src/gruffpy/rule/naming/boolean_prefix_rule.py` exposed the intended
string default. The fix was to quote the entry as `"yes"` in `.gruff-py.yaml`.

When adding string-list defaults to `.gruff-py.yaml`, quote YAML 1.1
boolean-like scalars such as `yes`, `no`, `on`, and `off`. The registry coverage
test is the right proof because it compares parsed config values against
`RuleDefinition.default_options`, not raw text.

## Lesson: Split regression tests by review surface before dogfood

**Created:** 2026-05-31
**Incident:** While adding correlated scoring coverage, one test asserted file
score, composite score, and pillar penalties together. The full pytest suite
passed, but `uv run gruff-py analyse src tests --fail-on advisory --no-baseline`
flagged `test-quality.eager-test` because the test had too many assertions.

When a regression spans multiple outputs, keep one test per reviewer surface
even if the setup is shared. This preserves the signal of
`test-quality.eager-test` and keeps dogfood aligned with the
reviewer-verification mission.

## Lesson: Tick task checkboxes when the proof passes, not during later cleanup

**Created:** 2026-05-31
**Incident:** After rerunning `scripts/preflight-checks.sh`, the agent reported
the worktree was clean but left the completed task
`.goat-flow/tasks/0.3.0/config-ignore-authority-and-check-ignore-v0.3.0.md`
with unchecked verification-gate boxes. The checks had passed in-session, but
the durable task state still said they were incomplete, forcing a later audit
and correction.

When a task file contains a checkbox for a command, evidence item, or exit
criterion, update that checkbox immediately after the proof passes. Before
final response, scan completed task files in the active task directory for
remaining `- [ ]` entries and either tick them with current evidence or explain
why the task is not actually complete.

## Lesson: When tool output lags or duplicates, re-establish ground truth before editing — never edit against a stale read, never confabulate the contents of output you do not have

**Created:** 2026-05-31
**Incident:** During an M07 session the harness began returning tool results
**delayed and duplicated** — later batches contained file-read content that did
not match the file on disk. The agent issued an `Edit` to
`src/gruffpy/rule/test_quality/magic_number_assertion_rule.py` based on a
*hallucinated* failing test (no such test existed; dogfood showed `0` findings
and `git grep '\.count\s*=='` over `tests`/`src` returned nothing), and five
further test-file edits failed `String to replace not found` because they
targeted stale read content. Worse, the agent then told the user the file had
"ballooned to 3000+ lines" — a detail it had **no tool output for** and
fabricated. Ground truth recovered only via cache-independent checks:
`md5sum <file>` vs `git show HEAD:<file> | md5sum` matched, `git status --short`
showed only the pre-existing dirty files, and `wc -l` matched HEAD. Net on-disk
change was zero; the "corruption" was lag, not damage.

When tool results arrive late, out of order, or duplicated, stop issuing
mutations and re-establish ground truth with checks that do not depend on a
possibly-stale read: `git status --short`, `md5sum` against
`git show HEAD:<path>`, `wc -l`, and a fresh `git diff --stat`. Two hard rules
follow. (1) Never run an `Edit` whose `old_string` came from a read you cannot
currently trust — re-Read or restore from HEAD first. (2) Never describe the
contents, size, or shape of tool output you did not actually receive; if a
result did not arrive, say "no output received", do not invent one. Fabricating
output detail is CLAUDE.md hallucination red-flag #4 ("looks like", "probably")
in its most dangerous form — a confident claim with zero evidence. Prefer
full-file `Write` over surgical `Edit` for recovery work, since a replayed
`Write` is idempotent while a replayed insert is not.

## Lesson: Posture map tests must move with rule catalogue additions

**Created:** 2026-06-02
**Incident:** While removing `security.dependency-unpinned-version`, focused
security verification failed in
`tests/unit/rule/test_reviewer_verification_posture.py` (search:
`_SENSITIVE_DATA_POSTURE`) because the M06 sensitive-data rules had been added
to `RuleRegistry.defaults()` but not to the reviewer-posture expectation map.
The security deletion itself was correct; the stale posture map blocked the
proof until `sensitive-data.gcp-service-account-key` and
`sensitive-data.url-credentials` were added to the expected posture.

When adding or deleting a default-enabled rule, update both catalogue/count
surfaces and any posture map that asserts whole rule families. Run
`uv run pytest tests/unit/rule/test_reviewer_verification_posture.py` with the
rule-family tests, not only the new rule's focused test, before considering the
catalogue stable.
