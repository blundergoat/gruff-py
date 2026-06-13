---
category: verification
last_reviewed: 2026-06-13
---

## Lesson: An Edit's new_string must re-include any trailing boundary its old_string captured as context

**Created:** 2026-06-13
**Incident:** While inserting the `## v0.4.1 - Unreleased` CHANGELOG section, the
first Edit used `old_string` ending in the existing `## v0.4.0 - 2026-06-11`
header (captured purely as an anchor) but the `new_string` ended at the new
v0.4.1 bullet and never re-included the `## v0.4.0` line. The header was
silently deleted, merging all of v0.4.0's bullets into the v0.4.1 section.
Five later CHANGELOG edits all anchored on v0.4.1 bullets, so none of them
re-touched the boundary and the corruption survived undetected until a
`grep -n "^## v0.4"` during the close-out status check returned only one match
instead of two.

**Fix / guard:** When an Edit's `old_string` reaches past the intended change
to grab a trailing structural marker (a section header, a closing brace/bracket,
a sentinel comment) only as insertion context, the `new_string` MUST reproduce
that marker verbatim at its end. After any prepend-or-insert edit to a
section-structured file (CHANGELOG, docs with `##` headers, ordered config
blocks), verify the structural invariant before moving on — e.g.
`grep -n '^## ' CHANGELOG.md` and confirm the expected number of section
headers, or count bullets per section. This is the editing analogue of the
existing footgun about confabulated tool output: do not assume an insert left
neighbouring structure intact — check it. See `.goat-flow/learning-loop/footguns/`
for the related "re-establish ground truth before editing" guidance.

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

## Lesson: Anchor-only aggregate filtering must include decorated headers

**Created:** 2026-06-08
**Incident:** While aligning symbol-scope changed-region filtering for
file/class aggregate findings, the first anchor-only implementation tested only
`finding.line`. Reading `src/gruffpy/rule/size/class_length_rule.py` (search:
`line=_start_line(node)`) and `src/gruffpy/rule/size/_lines.py` (search:
`decorators`) showed `size.class-length` anchors decorated classes at the first
decorator line, while `src/gruffpy/analysis/changed_region.py` declaration
ranges start at the `class` line. That meant an edit to the class header line
would suppress the class-length finding even though the edit touched the
aggregate anchor surface. The correction was to include the matching declaration
header line when anchoring symbol-scoped aggregate findings.

When changing anchor-only symbol filtering, test decorated declarations as well
as undecorated ones. The relevant anchor may be a small header range, not only a
single reported line.

## Lesson: New root commands must update the static root menu

**Created:** 2026-06-08
**Incident:** While adding the `hook` command for the agent-hook contract,
`tests/integration/test_hook_contract.py` proved direct invocation worked, but
the full CLI smoke suite failed because `gruff-py --help` did not list `hook`.
Reading `src/gruffpy/cli_menu.py` showed the root help screen is rendered from
a static `_root_menu_commands` list, separate from Click's command registry in
`src/gruffpy/cli.py`.

When adding or renaming a root command, update both the Click registration and
`src/gruffpy/cli_menu.py`, then run the full
`uv run pytest tests/integration/test_cli_smoke.py` rather than only invoking
the new command directly.

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

**Updated:** 2026-06-02. Dogfood later flagged the scp-style Git fixture string
`git@github.com:org/repo.git` as `sensitive-data.pii-test-fixture` because the
user/host segment is email-shaped. The correct fix was not to suppress the
finding or weaken real-email detection; it was to teach the PII rule that
`git@host:path` is a VCS reference while keeping realistic emails with ordinary
punctuation reportable.

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

## Lesson: Parser-confirmed comment heuristics need compound-header fixtures

**Created:** 2026-06-10
**Incident:** While making `waste.commented-out-code` tokenize only real COMMENT
tokens, the first implementation preserved parser confirmation but treated a
commented compound header such as `# if enabled:` as invalid Python. The focused
test failed (`test_commented_if_fires` expected one finding, got zero) because a
real commented-out block often appears as only the header line. The correction
was to probe colon-ended headers with an inserted `pass` body before rejecting
the comment as non-code.

When a source-text rule uses parser confirmation on snippets, include
single-line compound headers (`if`, `for`, `while`, `try`, `with`, `def`,
`class`) in counter-fixtures. A raw snippet can be incomplete yet still be a
high-signal commented-out-code shape.

## Lesson: Scan scratch repos from their own project roots

**Created:** 2026-06-10
**Incident:** While re-testing `.goat-flow/scratchpad/scan-test-repos/**`, the
first scan from the gruff-py repo root returned zero files because the dogfood
config ignores `.goat-flow/`. Adding `--include-ignored` fixed discovery but
changed semantics: `docs.missing-readme` evaluated the common
`scan-test-repos/` parent instead of each child repo. The correct reproduction
was to run `uv --project /path/to/gruff-py run gruff-py ... .` from inside each
target repo, preserving per-repo project-root rules and matching old file
counts.

When comparing scan-test repos under a scratch directory, validate
`filesParsed` and project-root findings before trusting timing or counts. A
fast zero-file scan and a parent-root README finding are setup bugs, not product
results.

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
**Updated:** 2026-06-10
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

The same trap recurred on 2026-06-05 while fixing
`test-quality.static-analysis-redundant-test` false positives:
`scripts/preflight-checks.sh` passed lint, mypy, docs, tests, and build, but the
Gruff self-check failed on `src/gruffpy/rule/test_quality/static_analysis_redundant_test_rule.py`
(search: `def _build_class_table`, search: `def _class_decl`) for nested,
cognitive, and cyclomatic complexity introduced by extra AST rebinding guards.
The correction was to extract statement-target and class-body collection helpers
(search: `def _module_bound_names`, search: `def _collect_class_child`) so the
runtime behaviour stayed covered by the same regression tests while the dogfood
gate could verify the implementation.

The same trap recurred on 2026-06-10 while adding custom generated-docs text
for `sensitive-data.pii-test-fixture`: focused tests, ruff, mypy, and docs
checks passed, but `uv run gruff-py analyse src/ tests/ --fail-on none
--format json` reported `size.file-length` and `size.function-length` on
`src/gruffpy/rule/catalog.py` (search: `def _custom_docs_for`). The correction
was to compact the new `RuleDocs` text so `catalog.py` stayed under 1000 lines
and `_custom_docs_for` stayed at the 100-line threshold.

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
the worktree was clean but left the completed config-ignore-authority and
check-ignore milestone task with unchecked verification-gate boxes. The checks had passed in-session, but
the durable task state still said they were incomplete, forcing a later audit
and correction.

When a task file contains a checkbox for a command, evidence item, or exit
criterion, update that checkbox immediately after the proof passes. Before
final response, scan completed task files in the active task directory for
remaining `- [ ]` entries and either tick them with current evidence or explain
why the task is not actually complete.

## Lesson: Keep self-check regression fixtures invisible to unrelated rules

**Created:** 2026-06-10
**Incident:** Running `scripts/preflight-checks.sh` after rule false-positive
work failed only the Gruff self-check. The failures were in test fixtures, not
runtime code: `tests/unit/rule/complexity/test_maintainability_index_rule.py`
(search: `test_lower_threshold_means_worse_mi_is_threshold`) had an inline
comment that looked like commented-out code,
`tests/unit/rule/sensitive_data/test_database_url_password_rule.py` (search:
`test_placeholder_password_skipped`) omitted parametrized ids, and the same
test assembled a complete secret-bearing database URL literal for a negative
case. The fix was to remove the code-shaped comment, add explicit `ids=`, and
build the URL fixture by concatenating the credential field instead of putting
the whole URL in one raw source string.

When editing regression fixtures for one rule, run the project dogfood check
before final preflight and inspect cross-rule fixture shapes. Negative fixtures
should still avoid complete secret-like literals, code-shaped comments, and
anonymous parametrized cases unless the test is explicitly exercising that rule.

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

## Lesson: Reproduce rule false-positive claims by running `gruff-py analyse` on a crafted fixture

**Created:** 2026-06-04
**Incident:** Assessing PR #5 coding-agent review claims that the new
`test-quality.static-analysis-redundant-test` rule emits false positives, the
agent verified by writing a small crafted test file and running
`uv run gruff-py analyse <dir> --format json --no-baseline`, then filtering the
JSON for the rule id. This confirmed four real false positives plus a
genuine-positive control - far stronger than code-reading alone - and separated a
real-but-rare bot finding (class-body nested rebind, kept) from a real-but-exotic
one with an over-broad proposed fix (metaclass hiding a method, fix rejected). The
first run returned `0` findings and grade A because the scratch path
`/tmp/gruff_repro` matched gruff-py's default ignore pattern `tmp`: the report
showed `filesDiscovered: 0`, `exitCode: 0`, `Composite: A (100.00 / 100)` -
visually identical to a clean pass. Recovered by re-running with
`--include-ignored`, which parsed the file and flagged all four.

When a review (bot or human) claims a rule fires, misses, or false-positives,
reproduce it by running `gruff-py analyse` on a minimal crafted fixture and
reading the findings for that rule id before agreeing or fixing - this is the
rule-behaviour analog of the `CliRunner` lesson above for CLI claims. Two gotchas:
(1) put the fixture on a path NOT covered by gruff-py's default ignores (anything
containing `tmp`, plus gitignored paths) or pass `--include-ignored`, because an
all-ignored scan reports zero findings, grade A, and exit 0 - check
`summary.filesParsed`/`filesDiscovered` before trusting a clean result. (2)
Include a known true-positive control in the fixture so a `0`-findings result
proves the rule is silent, not that the harness is mis-wired.

**Updated:** 2026-06-10. While implementing
`test-quality.extends-production-class`, the first CLI true-positive scratch
used `.goat-flow/scratchpad/0.4.0-M01/test_production_base.py` and returned
zero target findings even though the source shape was `class TestX(ProductionY)`.
Reading `src/gruffpy/rule/test_quality/extends_production_class_rule.py`
(search: `def _is_test_file`) showed the rule only runs for paths under
`tests/` or a top-level `test_*.py`; a nested filename alone is not enough. The
scratch repro passed only after moving it to
`.goat-flow/scratchpad/0.4.0-M01/tests/test_production_base.py`.

When crafting rule repros, mirror the rule's path gate as well as its source
shape. A true-positive source fixture can still report zero findings when the
file path prevents the rule from running.

## Lesson: Module-scope invalidation walks must cover nested statement blocks

**Created:** 2026-06-10
**Incident:** PR #6 review (Cursor Bugbot) flagged that
`src/gruffpy/rule/security/_security_node_helper.py` (search:
`def module_string_constants`) collected ALL-CAPS constant candidates from
top-level `tree.body` statements but only invalidated on `global` and `del`,
so a rebind nested in a module-level `if` or `try: import ... except
ImportError` block left a stale candidate propagating. The paired repro showed
`security.sql-concatenation` returning zero findings for `TABLE = "users"`
plus a conditional `TABLE = load_table_name()` rebind feeding
`cursor.execute(f"SELECT * FROM {TABLE}")`, because
`is_fixed_string_expression` resolved the f-string through the stale constant.
The same review round refuted a sibling bot claim (async `def _` escaping the
dead-code prefilter) by running the regex live, so each claim was repro-tested
before accepting or rejecting it. Fixed by walking module scope with
function/class/lambda bodies pruned and invalidating every Store-context
ALL-CAPS name outside its recording assignment (search:
`_module_scope_rebound_names`).

When an allowlist depends on "single assignment at module scope", iterating
`tree.body` alone is not single-assignment proof: rebinds hide in nested
module-level blocks, loop targets, tuple unpacking, and walrus expressions.
Pair the collector tests with nested-rebind fixtures
(`tests/unit/rule/security/test_security_node_helper.py`, search:
`conditional_module_scope_rebinds`) and keep a function-local shadow fixture
proving scope pruning still propagates legitimate constants.

## Lesson: `except tokenize.TokenError` is not enough, and one site is never all sites

**Created:** 2026-06-11
**Incident:** PR #6 review (Cursor Bugbot, rated Low) noted
`waste.commented-out-code` returned zero comments when `tokenize` raised
`TokenError`. Double-checking escalated it twice. First, the tokenizer raises
`IndentationError` (a `SyntaxError`, not a `TokenError`) on bad dedents, and
source-text scanners run on unparseable files, so a single file like
`def f():\n    pass\n  bad = 1` crashed the entire `gruff-py analyse` run with
an uncaught traceback - the registry has no per-rule exception isolation.
Second, fixing the rule did not fix the crash: the new integration test
(`tests/integration/test_cli_smoke.py`, search:
`tokenizer_error_file_reports_parse_error`) still failed because
`src/gruffpy/suppression/parser.py` (search: `_comment_tokens`) and
`src/gruffpy/rule/docs/_comment_scanner.py` had copies of the same narrow
`except tokenize.TokenError`. All three now catch
`(tokenize.TokenError, SyntaxError)` and keep tokens collected before the
failure.

When fixing an exception-handling gap, grep for every other call site of the
same API (`generate_tokens`) before declaring the fix done, and verify with an
end-to-end repro (real CLI on a broken file), not only the unit test of the
site you first fixed - the unit test passed while the CLI still crashed.

## Lesson: Mirror Load-context guards across every reference-recording visitor path

**Created:** 2026-06-11
**Incident:** PR #6 review round 4 (Cursor Bugbot) flagged that
`src/gruffpy/rule/design/single_implementor_protocol_rule.py` (search:
`def visit_Attribute`) recorded every attribute node as a value reference
while `visit_Name` required `ast.Load`. Repro: a monkeypatch-style store
target `rendering.Renderer = FakeRenderer` cleared the single-implementor
finding (1 finding without the file, 0 with it) even though it binds an
attribute *named* like the abstraction without referencing it. Fixed by
mirroring the `Load` check in `visit_Attribute`; the loaded inner chain
(`a.Renderer` in `a.Renderer.x = 1`) still counts via `generic_visit`, and
`del module.X` stops counting. The bot's companion claim that leaf matching
in `_is_matching_name` is a co-culprit was declined: leaf matching is the
deliberate no-import-resolution evidence model and errs in the
finding-suppressing direction.

When a `NodeVisitor` counts references, every recording path (`visit_Name`,
`visit_Attribute`, any future handler) must apply the same `expr_context`
discipline. Pair a store-target fixture with a load-usage fixture
(`tests/unit/rule/design/test_single_implementor_protocol_rule.py`, search:
`attribute_store_target_alone_still_flags`).
