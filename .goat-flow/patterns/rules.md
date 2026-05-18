---
category: rules
last_reviewed: 2026-05-13
---

## Pattern: Add rules end to end

**Context:** New rules need to participate in config defaults, selection, execution, reporting, scoring, and tests.

**Approach:** Implement the rule under the relevant `src/gruffpy/rule/<pillar>/` package, return a complete `RuleDefinition`, register it in `RuleRegistry.defaults()`, and cover thresholds/metadata/severity with a focused test under `tests/unit/rule/`. Add or update a CLI integration assertion when the new rule changes report shape, exit-code behaviour, or output ordering.

## Pattern: Split severity thresholds from named tuning knobs

**Context:** gruff-php and gruff-py support two different numeric config shapes. Rubric thresholds that map directly to finding severity use one `threshold` plus one `severity`; rule-specific tuning values use the `thresholds` table with semantic names.

**Approach:** For rules whose built-in defaults are exactly `warning` and `error`, expose config as `rules.<id>.threshold` and `rules.<id>.severity`, and route rule findings through `RuleSettings.high_value_threshold_match()` or `low_value_threshold_match()`. For non-severity knobs, keep `rules.<id>.thresholds.<name>` and choose names that describe the measured concept, such as `maxAssertions` or `minGroupSize`, not severity labels.
