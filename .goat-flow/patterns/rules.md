---
category: rules
last_reviewed: 2026-05-24
---

## Pattern: Add rules end to end

**Context:** New rules need to participate in config defaults, selection, execution, reporting, scoring, and tests.

**Approach:** Implement the rule under the relevant `src/gruffpy/rule/<pillar>/` package, return a complete `RuleDefinition`, register it in `RuleRegistry.defaults()`, and cover thresholds/metadata/severity with a focused test under `tests/unit/rule/`. Add or update a CLI integration assertion when the new rule changes report shape, exit-code behaviour, or output ordering.

## Pattern: Split severity thresholds from named tuning knobs

**Context:** gruff-php and gruff-py support two different numeric config shapes. Rubric thresholds that map directly to finding severity use one `threshold` plus one `severity`; rule-specific tuning values use the `thresholds` table with semantic names.

**Approach:** For rules whose built-in defaults are exactly `warning` and `error`, expose config as `rules.<id>.threshold` and `rules.<id>.severity`, and route rule findings through `RuleSettings.high_value_threshold_match()` or `low_value_threshold_match()`. For non-severity knobs, keep `rules.<id>.thresholds.<name>` and choose names that describe the measured concept, such as `maxAssertions` or `minGroupSize`, not severity labels.

## Pattern: Regression-test same-shape expression false positives

**Context:** Analyzer helpers that compare AST expressions can accidentally treat
same-shaped calls on different receivers as identical. The
`test-quality.tautological-type-assertion` rule previously treated
`a.fingerprint() == b.fingerprint()` as a tautology because it compared only the
call target leaf and arguments, not the receiver expression.

**Approach:** When fixing expression-comparison rules, add both a positive
same-expression fixture and a negative same-shape/different-receiver fixture.
Keep the negative fixture close to the rule test, as in
`tests/unit/rule/test_quality/test_tautological_type_assertion_rule.py`, so
future simplifications must prove they still distinguish receiver identity.

## Pattern: Use `ast.Call` presence to distinguish Acts from data unpacking

**Context:** Test-quality heuristics often need to discriminate between a
"real operation" (Act) and "data unpacking" (subscript / attribute access /
literal or dict-comp restructuring) between assertions. The original
`test-quality.multiple-aaa-cycles` rule treated *any* non-assert statement
as a cycle boundary, which over-fired on the common patterns
`finding = findings[0]`, `payload = json.loads(result.output)`,
`assert isinstance(x, T)` type-narrowing, and dict-comp restructuring -
all of which keep the test inside one Assert phase.

**Approach:** When a heuristic must decide "is this a new Act or still the
Assert phase?", use
`any(isinstance(n, ast.Call) for n in ast.walk(stmt))` as the boundary
predicate. Pure attribute / subscript / literal statements with no `Call`
should not advance rule state. Pair the rule with fixtures that exercise
*both* shapes - a real-call boundary AND an access-only restructure - so
future simplifications must keep distinguishing them. See
`src/gruffpy/rule/test_quality/multiple_aaa_cycles_rule.py` (`_has_call`)
and the access-only fixtures in
`tests/unit/rule/test_quality/test_multiple_aaa_cycles_rule.py`.
