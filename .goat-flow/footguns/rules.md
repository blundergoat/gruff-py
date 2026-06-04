---
category: rules
last_reviewed: 2026-06-04
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

## Footgun: static declaration evidence is not proof of runtime existence

**Status:** active | **Created:** 2026-06-04 | **Evidence:** OBSERVED

A "static-analysis-redundant" style rule that treats a name's presence in the
parsed class/module body as proof the member exists on the runtime object will
false-positive wherever Python rebinds that name.
`src/gruffpy/rule/test_quality/static_analysis_redundant_test_rule.py`
(search: `def _build_class_table`) marks a class name ambiguous for module-level
`Import`, `ImportFrom`, `Assign`, and `AnnAssign` with a `Name` target, but the
guard is under-inclusive. It does NOT cover: (1) a module-level `def`/`async def`
shadowing a same-name class; (2) a class-body rebinding of a nested name
(search: `def _class_decl` keeps `nested[child.name]` even after a later
`Inner = 1`); (3) a function-local binding inside the test (the scan passes only
the module table to `_match_assertion`, search: `def _match_assertion`); or (4) an
attribute write `Class.member = ...` / `del Class.member` (the `Assign` branch
filters targets to `ast.Name`, so `ast.Attribute` targets slip through). All four
were reproduced this session by running `gruff-py analyse` on a crafted fixture -
`def Alpha()` after `class Alpha`, `class Inner` then `Inner = 1`, a local
`Gamma = ...`, and `Beta.render = None` each flagged as "redundant" while the
runtime assertion was not redundant. PR #5 bot review (CodeRabbit, Codex)
surfaced subsets. The rule is on by default at ADVISORY, and since the default
`--fail-on` is `advisory` (ADR-019) each false positive can fail a default CI run.

When writing or porting any rule whose evidence is "symbol declared in source ⇒
member exists at runtime," build the ambiguity/shadowing set over every rebinding
shape, not just module-level `Name` rebinds: import, module-level `def`/`async
def`, `Assign`/`AnnAssign` with a `Name` target, `Assign`/`Delete` with an
`Attribute` target (`Class.member`), in-body rebinds of nested names, and
function-local bindings. The test-quality pillar already tracks function-local
rebindings for the mock case
(`src/gruffpy/rule/test_quality/_test_quality_node_helper.py`,
search: `def find_mock_bindings`), so the precedent for "a local binding poisons
the static reading" exists in-pillar. Prove the guard with a crafted fixture
before trusting it - see `.goat-flow/lessons/verification.md`
(search: `crafted fixture`).
