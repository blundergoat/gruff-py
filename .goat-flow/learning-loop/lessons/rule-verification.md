---
category: rule-verification
last_reviewed: 2026-10-03
---

## Lesson: New test docstrings need complete fixture and failure contracts before dogfood

**Created:** 2026-07-12
**Incident:** During safe `init --force` verification, focused tests, ruff, and
mypy were green, but the required dogfood scan failed on seven documentation
findings in newly rewritten tests. Four journey docstrings described the
behavior but omitted their `tmp_path` and `monkeypatch` parameters; a nested
filesystem-failure helper omitted both parameters and its deliberate
`OSError`; one schema-recovery test omitted `tmp_path`. Adding the missing
`Args` and `Raises` contracts made the same dogfood reproduction return zero
findings without changing test behavior. The same trap recurred while hardening
Markdown sanitizer provenance: 20 parametrized rule tests had concise behavior
docstrings but no `Args` entries, and dogfood—not pytest, ruff, or mypy—was the
first gate to reject them.

The same trap recurred during scalar Boolean annotation verification: seven
new parametrized matrix tests described the scan behavior but omitted their
parameter contracts. Focused pytest, ruff, and mypy were green; the root
dogfood scan reported all seven `docs.missing-param-doc` findings. Adding exact
`Args` entries for declaration templates, metadata kinds, and annotation
spellings cleared that surface without changing an assertion.

Before broad dogfood, check every new or materially rewritten test docstring
against its full signature, including pytest fixtures. A nested helper that
models a user-visible failure also documents the exception it deliberately
raises. Focused pytest and static type checks do not cover these documentation
rules because the project analyser scans `tests/` as product-quality code.

## Lesson: Keep invariant assertions at the collected test boundary

**Created:** 2026-07-12
**Incident:** A parametrized current-document invariant delegated its only
`assert` statement to a custom helper. Pytest, ruff, format, mypy, and the
focused negative fixture all passed, but root dogfood reported
`test-quality.no-assertions` because the collected test body only called the
helper. Recasting the helper as a detector that returns matched evidence let
the collected test assert the user-visible invariant directly.

**Evidence:** `tests/unit/command/test_rule_docs.py` (search:
`def test_live_catalog_totals_are_generated_only`) now asserts the result of
`_live_catalog_total_in` in the collected test. The rule intentionally inspects
the collected function body for assertion statements and recognized assertion
calls in `src/gruffpy/rule/test_quality/no_assertions_rule.py` (search:
`def _has_any_assertion`); it does not follow arbitrary helper bodies.

**Prevention:** Let invariant helpers collect or normalize evidence, then place
the decisive assertion in each collected test. After adding parametrized
repository invariants, run root dogfood even when focused pytest and static
gates are green.

## Lesson: File-size splits must expose cross-file helper ownership

**Created:** 2026-07-12
**Status:** historical
**Reason:** `dead-code.unused-private-function`, which reported the cross-file
private helpers, was retired in 0.6.0 (ADR-029). The principle still applies:
name a helper by who uses it, and run root dogfood right after a split.
**What happened:** The Markdown sanitizer provenance helper exceeded the
project's 1,000-line error threshold, so it was split into a statement index and
a flow model. Seven underscore-prefixed model functions were imported and used
by the sibling index, but `dead-code.unused-private-function` intentionally
checks a private function's enclosing module and reported every one as unused.
Renaming only the cross-file API to public names inside the still-private module
made ownership honest; module-internal helpers remained private.
**Evidence:**
`src/gruffpy/rule/security/_markdown_sanitizer_model.py` (search:
`def combine_expression_safety`) and
`src/gruffpy/rule/security/_markdown_sanitizer_provenance.py` (search:
`combine_expression_safety`) — the defining and consuming anchors are now
explicit, and the repeated root dogfood scan returned zero findings.
**Prevention:** Before splitting a large module, classify each moved symbol as
module-internal or cross-file API. Give cross-file helpers public names even
when their module is private, add full return/field documentation during the
move, and run root dogfood immediately after the split rather than relying on
import-aware lint or type checks.

## Lesson: Parametrize case ids must use the checked decorator surface

**Created:** 2026-07-12
**What happened:** A three-case Boolean naming test used
`pytest.param(..., id=...)` for every row, so pytest displayed readable case
names and focused/static gates passed. Root dogfood still reported
`test-quality.parametrize-annotation` because the project contract checks for
the decorator-level `ids=` keyword. Moving the same labels to `ids=[...]`
cleared the finding without changing cases or assertions.
The trap recurred on 2026-08-05 in
`tests/unit/rule/security/test_ssrf_rule.py` (search:
`def test_rebound_http_client_method_stays_quiet`): every `pytest.param` row
already had an `id=`, but root dogfood still required the checked decorator's
own `ids=` surface.
It recurred again on 2026-08-06 in the same file's source-order matrix:
five readable row-level ids did not satisfy the rule until the decorator
received its explicit `ids=` tuple.
**Evidence:**
`src/gruffpy/rule/test_quality/parametrize_annotation_rule.py` (search:
`def _parametrize_candidate`) checks `call_keyword(decorator, "ids")`, while
`tests/unit/rule/naming/test_boolean_prefix_rule.py` (search:
`def test_vague_boolean_names_still_fire`) now supplies that exact surface.
**Prevention:** For any literal parametrization above the configured case
threshold, put human-readable labels in the decorator's `ids=` argument even
when individual `pytest.param` rows could carry their own ids. Run root
dogfood because pytest, ruff, and mypy do not enforce this repository contract.

## Lesson: Predicate helper names are dogfood contracts

**Created:** 2026-08-05
**What happened:** Focused pytest, ruff, and mypy were green, but root dogfood
rejected two new Boolean-returning helpers whose names did not use the
repository's predicate vocabulary. Renaming them preserved behavior and
cleared both `naming.boolean-prefix` findings. The companion tri-state
receiver resolver was made an explicit status value instead of disguising
`bool | None` as a predicate.
The source-order follow-up repeated the naming trap once:
`_binding_shadows_call` returned Boolean but lacked a registered prefix;
`_is_call_shadowed_by_binding` made the predicate contract explicit.
**Evidence:** `src/gruffpy/rule/security/ssrf_rule.py` (search:
`def _scope_client_binding_status`, search: `def _has_name_binding`) and
`src/gruffpy/rule/size/file_length_rule.py` (search:
`def _is_inside_docstring_span`) contain the corrected predicate anchors.
**Prevention:** Name Boolean-returning helpers for their predicate contract
before the first root dogfood run; static tooling does not enforce the
project's intent vocabulary.

## Lesson: Rebinding guards need execution order and Python scope semantics

**Created:** 2026-08-06
**Incident:** PR #9's current-head review found that SSRF import proof treated
every later store as if it had already shadowed the call. The RED matrix
suppressed four real `requests.get` calls before later function-member,
same-line member, module-name, and class-name stores. A control with a later
function-local name assignment also stayed quiet, which is correct because
Python makes that name local for the whole function.
The first GREEN implementation then pushed `_scope_client_binding_status` to
cognitive 37 and cyclomatic 24; extracting import classification and
non-import shadow decisions made the exact dogfood reproduction clean.
The same guard failed again in the opposite direction on 2026-08-08: it
returned `shadowed` at the *first* module-scope store and never reached a
later canonical import, so `requests`, `httpx`, bare `urlopen`, and qualified
`urllib.request.urlopen` calls inside a function all stayed quiet even though
the whole module executes before the endpoint runs. That silence contradicted
both the module docstring's "live when the call executes" promise and the
already-pinned trailing-import test one scope away.

**Evidence:** `src/gruffpy/rule/security/ssrf_rule.py` (search:
`def _scope_client_binding_status`, search: `def _is_after_call`) now
compares line and column positions for directly executed scopes, retains
retroactive function-local names, and accumulates the last effective binding
instead of returning on the first shadow.
`tests/unit/rule/security/test_ssrf_rule.py` (search:
`def test_later_non_retroactive_rebinding_keeps_earlier_supported_call`)
pins member, module, class, same-line, global, local-assignment, and local-import
cases; (search: `def test_restoring_module_import_after_shadow_proves_receiver`,
search: `def test_module_shadow_after_import_keeps_call_quiet`) pins both
directions of the shadow/import matrix across all four receivers.

**Prevention:** A lexical binding collector cannot answer “what object did this
call use?” from scope membership alone. Separate retroactive function-local
bindings from source-ordered module, class, attribute, global, and nonlocal
stores, and include a same-line case whenever columns decide execution order.
Resolve a source-ordered scope by the *last* effective binding, never the first
match - an early `return "shadowed"` silently converts a restoring rebind into
a false negative. Whenever a guard has two directions, pin both in one matrix.

## Lesson: Generated Python fixtures need a minimum-runtime execution gate

**Created:** 2026-07-16
**Incident:** The Markdown sanitizer test helper generated f-strings whose
double-quoted expressions reused the outer double quote. Python 3.12 accepted
that PEP 701 grammar, so local verification passed, but the supported Python
3.11 CI job failed 23 tests before exercising their assertions. During repair,
the first isolated 3.11 command also omitted the optional development
dependencies and could not spawn pytest; adding `--all-extras` reproduced the
actual CI environment without mutating the repository virtualenv. The first
runtime repair also validated string-valued `ast.Constant` nodes in one loop
and consumed them in a later loop; mypy correctly rejected the non-local
narrowing until the consuming branch repeated the value-type check.

**Evidence:** `tests/unit/rule/security/test_unsanitized_markdown_interpolation_rule.py`
(search: `def _link_source`) now uses a triple-quoted outer f-string, and its
full module runs through:
`uv run --isolated --locked --all-extras --python 3.11 pytest -o addopts=''
tests/unit/rule/security/test_unsanitized_markdown_interpolation_rule.py`.

**Prevention:** When tests generate source code, treat the generated text as a
compatibility artifact. Run the affected module on the minimum supported
interpreter, with the project's development extra, before relying on the
default interpreter's parser or starting the full release gate. When an AST
value's concrete type matters, narrow it in the branch that consumes it instead
of assuming a prior traversal will carry type information forward.

**2026-08-06 follow-up:** The environment trap recurred when a focused command
used `uv run --python 3.11 pytest` without `--isolated --locked --all-extras`.
uv replaced the repository virtualenv with a runtime-only environment, then
could not spawn pytest. Reuse the proven isolated command above verbatim; the
flags protect both dependency coverage and the user's working virtualenv.

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
`src/gruffpy/rule/catalog.py` for the then-monolithic `_custom_docs_for` factory.
The correction was to compact the new `RuleDocs` text so `catalog.py` stayed
under 1000 lines and that factory stayed at the 100-line threshold; the per-rule
custom-docs factories have since been extracted to
`src/gruffpy/rule/catalog_docs.py` (search: `def custom_docs_for`).

The trap recurred during scalar Boolean annotation work: one new
`BooleanPrefixRule` match arm raised `custom_docs_for` from the allowed
cyclomatic complexity of 20 to 21 even though focused tests, ruff, mypy, and
generated-doc checks were green. The correction shares one naming-rule match
arm and dispatches both naming documentation factories through
`_naming_rule_docs` (same file), preserving the existing branch count without
removing either rule card. Before extending a near-threshold dispatcher, share
an existing family arm or extract a branch-free keyed dispatch, then rerun root
dogfood.

The same two shapes recurred during cross-module private-function liveness
work. A separate dead-code catalog arm again raised `custom_docs_for` to 21,
while one 118-line import/load collector crossed cyclomatic, cognitive,
maintainability, and function-length thresholds. Sharing the dead-code arm via
branch-free keyed dispatch and splitting binding collection from attribute/name
load handling removed all five errors without changing focused outcomes. Treat
one materialized AST walk as a data boundary, not a reason to keep both
in-memory processing stages in one function.

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

**Updated:** 2026-07-12. The first ambiguous-module CLI proof used `app` and
`vendor` as duplicate package source roots, but discovery default-ignored the
latter; only one producer reached the resolver and the expected two LOW
findings did not appear. Replacing the second temporary root with `lib` made
the duplicate visible and the full matrix passed. For multi-file ambiguity
fixtures, verify every intended path appears in discovery (or deliberately use
`--include-ignored`) before interpreting resolver counts.

## Lesson: Inline parametrize case tables count toward test length

**Created:** 2026-10-03
**Decision changed:** Put a long parametrize case table in a module-level `_..._CASES` tuple, with readable ids, before running the dogfood self-check.
**Trigger phase:** ACT
**Caught at:** VERIFY
**Incident:** CI's Gruff self-check failed on 7823c47 and b40d306. Seven of its
28 findings were errors on three tests whose bodies were short:
`test_own_workflow_event_guard`, `test_shared_entropy_policy` and
`test_source_proven_framework_roles` reported `size.function-length` and
`test-quality.test-function-too-long` at 195 to 242 lines, and one also failed
`complexity.maintainability-index`. ADR-002 measures a function from its first
decorator line, so each inline case table counted as test body. Moving the
tables to module-level constants cleared all seven errors with every pytest
node id unchanged, and a value-level dump of all collected cases matched before
and after.

`test-quality.parametrize-annotation` counts only literal tables,
`src/gruffpy/rule/test_quality/parametrize_annotation_rule.py` (search: `case_count = len(cases.elts)`),
so a named constant also stops it asking for `ids=`. Name the rows anyway, with
`pytest.param(..., id=...)` or a sibling `_..._IDS` tuple, as
`tests/unit/rule/security/test_github_actions_secrets_in_pr_rule.py` (search: `_OWN_WORKFLOW_EVENT_GUARD_IDS`) does.

## Lesson: A safe-form check proves nothing for a rule the fixture never exercises

**Created:** 2026-10-05
**Decision changed:** Before claiming a safe fixture covers a rule, add the rule's safe call shape and show an unsafe copy of it fires.
**Trigger phase:** ACT
**Caught at:** VERIFY
**Prevention:** An empty finding list from a safe fixture only covers the rules
whose call shapes the fixture contains. For each rule a safe test claims, put
its safe form in the fixture, then rewrite that form unsafely in a scratch copy
and confirm the rule fires on it.

**Incident:** Turning `security.django-raw-sql` off by default (ADR-029) made
the security pillar's safe test enable it again, with a comment saying its
parameterised raw-SQL form stayed checked. The fixture had no Django import and
no `.raw` or `RawSQL` call, so the rule's framework gate ruled the file out and
the test passed whatever the rule did. The first review found the test checked
nothing for the off rules; the fix added the enabling call but still no raw-SQL
call, and a second review caught it. The fixture now carries parameterised
`Model.objects.raw` and `RawSQL` calls, and their f-string copies fire both
shapes: `tests/unit/rule/security/test_security_pillar_integration.py`
(search: `def test_safe_equivalents_emit_no_security_findings`).
