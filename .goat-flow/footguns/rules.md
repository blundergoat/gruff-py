---
category: rules
last_reviewed: 2026-06-05
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
(`src/gruffpy/rule/catalog.py`, search: `class RuleDocs`) - specifically
`rationale`, `fix_guidance`, `bad_example`, `good_example`, or
`confidence_rationale`. `RuleDocs` carries the curated and auto-generated
prose; `RuleDefinition` carries hot-path data that travels with every
`Finding`. The split is deliberate. If you genuinely need a new short
label on `RuleDefinition`, name the new field for the constraint rather
than reusing `description` - the existing field's contract is "short
display label."

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
`Attribute` target (`Class.member`), in-body rebinds of nested names, and
function-local bindings. Keep regression tests in
`tests/unit/rule/test_quality/test_static_analysis_redundant_test_rule.py`
(search: `test_module_level_function_rebinding_makes_class_ambiguous`,
search: `test_module_level_member_rebinding_makes_method_ambiguous`,
search: `test_nested_class_rebinding_makes_nested_class_ambiguous`,
search: `test_test_local_rebinding_makes_class_ambiguous`). Prove the guard with
a crafted fixture before trusting it - see `.goat-flow/lessons/verification.md`
(search: `crafted fixture`).
