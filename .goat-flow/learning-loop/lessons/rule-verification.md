---
category: rule-verification
last_reviewed: 2026-08-05
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
rejected three new Boolean-returning helpers whose names did not use the
repository's predicate vocabulary. Renaming them preserved behavior and
cleared all three `naming.boolean-prefix` findings. The tri-state receiver
resolver was made an explicit status value instead of disguising `bool | None`
as a predicate.
**Evidence:** `src/gruffpy/rule/security/ssrf_rule.py` (search:
`def _scope_client_binding_status`, search: `def _has_name_binding`) and
`src/gruffpy/rule/size/file_length_rule.py` (search:
`def _is_inside_docstring_span`) contain the corrected predicate anchors.
**Prevention:** Name Boolean-returning helpers for their predicate contract
before the first root dogfood run; static tooling does not enforce the
project's intent vocabulary.

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
