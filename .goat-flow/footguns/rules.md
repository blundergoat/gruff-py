---
category: rules
last_reviewed: 2026-05-27
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
