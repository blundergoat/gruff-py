---
category: rules
last_reviewed: 2026-06-14
---

## Footgun: `RuleDefinition.description` is a short label, not sentence-level prose

**Status:** active | **Created:** 2026-05-27 | **Evidence:** ACTUAL_MEASURED

`RuleDefinition.description` (`src/gruffpy/rule/definition.py`, search:
`description: str = ""`) carries a 9-38 character label across the 115-rule
catalogue (mean 21 chars). Real values look like `"Cognitive complexity"`,
`"Halstead volume"`, `"Nesting depth"` - essentially the rule name with
sentence case, not prose. The `get_description()` fallback to `self.name`
reinforces the label intent (`src/gruffpy/rule/definition.py`, search:
`def get_description`). Designing any feature that wants per-rule sentence
prose (a description column in `summary --group-by=rule`, a Markdown
catalogue entry, a `list-rules` detail view paragraph) against
`definition.description` produces output that mostly duplicates the rule id
("`complexity.npath`  Cognitive complexity"). Hit twice in 2026-05-27 -
once while scoping M03's summary grouping (rejected the description column
on this basis) and once while scoping M04's explain mode (which uses
`RuleDocs.rationale` instead).

When a feature wants per-rule sentence prose, source it from `RuleDocs`
(`src/gruffpy/rule/catalog_docs.py`, search: `class RuleDocs`; moved out of
`catalog.py` 2026-06-13 for the file-length rule, re-exported from
`gruffpy.rule.catalog`) - specifically
`rationale`, `fix_guidance`, `bad_example`, `good_example`, or
`confidence_rationale`. `RuleDocs` carries the curated and auto-generated
prose; `RuleDefinition` carries hot-path data that travels with every
`Finding`. The split is deliberate. If you genuinely need a new short
label on `RuleDefinition`, name the new field for the constraint rather
than reusing `description` - the existing field's contract is "short
display label."

## Footgun: per-function rules that bare-`ast.walk` a function descend into nested scopes

**Status:** active | **Created:** 2026-06-13 | **Evidence:** OBSERVED

A per-function rule that calls `ast.walk(function)` to collect call sites,
assignments, or guards visits nested `def` / `class` / `lambda` bodies too.
Because the rule's top-level pass also analyses each nested function in its own
right, the same conversion/scan is emitted from both the enclosing and the
nested scope (a duplicate finding at one line), and outer-scope evidence
(isnumeric guards, defensive signatures, float sources) wrongly applies to
inner-scope code. PR #8 hit this in both new correctness rules: two stacked
all-untyped functions where the inner did `number = float(y); int(number)`
flagged the inner conversion twice, and a free-text scan inside a nested
function was attributed to the outer scope as well.

When a rule's unit of analysis is a single lexical scope, walk it with the
scope-limited helpers, never bare `ast.walk(function)`: cross-pillar rules use
`gruffpy.rule._ast_scope` (`walk_function_scope` for a function root,
`walk_statement_scope` for a statement that may itself be a nested `def`);
complexity rules already have `gruffpy.rule.complexity._walks`
(`body_nodes`, search: `without descending into nested scopes`). The trap is
recurring - `_walks.py` exists for exactly this reason, and the correctness
rules re-introduced it. Fixed sites:
`src/gruffpy/rule/correctness/substring_vocabulary_match_rule.py`
(search: `_scan_function`, `_parameter_text_sources`) and
`src/gruffpy/rule/correctness/unsafe_numeric_coercion_rule.py`
(search: `_coercion_calls`, `_float_assignment_sources`,
`_isfinite_argument_names`).

## Footgun: `dead-code.exported-but-unreferenced` flags `__all__` exports by design - the library noise is not a bug

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

`dead-code.exported-but-unreferenced`
(`src/gruffpy/rule/dead_code/exported_but_unreferenced_rule.py`) deliberately
counts `__all__` membership and bare re-export imports as NON-use: a public
symbol re-exported through a package `__init__` and listed in `__all__` but never
called anywhere in the project IS flagged. That is the rule's whole point -
"export is not use," export plumbing keeps a dead symbol looking alive. On a
full-project scan of a LIBRARY it therefore fires across the public API: a
2026-06-14 scan of the `supervision` corpus flagged 18 intentional public
symbols (`DetectionsSmoother`, `draw_line`, `IconAnnotator`, ...) whose only
in-repo references were the `__init__` re-export, the `__all__` entry, and
docstring examples.

This reads like a false-positive flood, and the obvious "fix" - exempt
`__all__`-listed symbols - is WRONG: it guts the rule and breaks its canonical
test (`tests/unit/rule/dead_code/test_exported_but_unreferenced_rule.py`,
search: `test_dead_export_in_all_plus_reexport_fires`), which asserts an
`__all__` + re-export + uncalled symbol fires. The rule is app-oriented by
design; the library escape hatch is config (`allowlists.deadCode`,
`entryPointPatterns`), not a detection change. Before "fixing" apparent FPs in an
advisory rule, grep its tests for one that asserts the exact behaviour.

## Footgun: rules that read `x in y` as substring containment false-positive on collection-typed `y`

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

`in` is overloaded: `term in text` is substring containment for a `str`, but
membership for a `dict` / `set` / `list` / `Mapping`. A rule that matches the
`x in y` AST shape and assumes substring semantics fires on intentional
key/element membership. `correctness.substring-vocabulary-match` hit this on a
2026-06-14 corpus scan: `any(k in tool_input for k in VOCAB)` with
`tool_input: dict[str, Any]` was flagged as substring routing only because the
name carried the `input` free-text token - it is dict-key membership, not
copy routing.

When a rule interprets a containment or comparison operator semantically, gate
on the operand's TYPE, not just its name. The fix
(`src/gruffpy/rule/correctness/substring_vocabulary_match_rule.py`, search:
`_is_collection_annotated`, `_COLLECTION_ANNOTATIONS`) excludes parameters whose
annotation head is a known non-`str` collection; `_annotation_head_names` (same
file) unwraps `dict[..]`, `typing.Dict`, and `X | None` to the head type.

## Resolved Entries

## Footgun: static declaration evidence is not proof of runtime existence

**Status:** resolved | **Created:** 2026-06-04 | **Resolved:** 2026-06-05 | **Evidence:** OBSERVED

Before the 2026-06-05 fix, the
`test-quality.static-analysis-redundant-test` rule treated a name's presence in
the parsed class/module body as proof the member existed on the runtime object,
which false-positived wherever Python rebound that name.
`src/gruffpy/rule/test_quality/static_analysis_redundant_test_rule.py`
(search: `def _build_class_table`) marks a class name ambiguous for module-level
`Import`, `ImportFrom`, `Assign`, `AnnAssign`, module-level `def`/`async def`,
and module-level `Delete`/`AugAssign` targets. It now also marks
`Class.member` writes/deletes ambiguous through `_mark_attribute_rebinding`
(search: `def _mark_attribute_rebinding`), class-body member shadowing through
`_with_ambiguous_member` (search: `def _with_ambiguous_member`), and test-local
bindings through `_local_rebindings` (search: `def _local_rebindings`). The four
original false positives were: `def Alpha()` after `class Alpha`,
`class Inner` then `Inner = 1`, a local `Gamma = ...`, and
`Beta.render = None`.

When writing or porting any rule whose evidence is "symbol declared in source ⇒
member exists at runtime," build the ambiguity/shadowing set over every rebinding
shape, not just module-level `Name` rebinds: import, module-level `def`/`async
def`, `Assign`/`AnnAssign` with a `Name` target, `Assign`/`Delete` with an
`Attribute` target (`Class.member`), in-body rebinds of nested names,
function-local bindings, bindings nested inside class-body or module-scope
compound bodies (`if`/`for`/`while`/`with`/`try`/`match` - you must descend the
bodies, not just inspect the compound node's own targets, which are empty), and
`match` capture patterns (`case Widget:` is a capture that rebinds `Widget`, not
a value match against the class). The 2026-06-09 pass added the last two shapes:
class bodies now descend via `_record_conditional_class_bindings` /
`_is_compound_statement`, and module scope via a `match_case` branch in
`_module_scope_statements` plus `_match_capture_names` (all in
`src/gruffpy/rule/test_quality/static_analysis_redundant_test_rule.py`). Keep
regression tests in
`tests/unit/rule/test_quality/test_static_analysis_redundant_test_rule.py`
(search: `test_module_level_function_rebinding_makes_class_ambiguous`,
search: `test_class_body_conditional_rebinding_makes_member_ambiguous`,
search: `test_match_case_body_rebinding_makes_class_ambiguous`,
search: `test_match_capture_pattern_makes_class_ambiguous`). Prove the guard with
a crafted fixture before trusting it - see `.goat-flow/learning-loop/lessons/verification.md`
(search: `crafted fixture`).
