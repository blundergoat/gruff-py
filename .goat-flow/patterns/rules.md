---
category: rules
last_reviewed: 2026-05-13
---

## Pattern: Add rules end to end

**Context:** New rules need to participate in config defaults, selection, execution, reporting, scoring, and tests.

**Approach:** Implement the rule under the relevant `src/gruffpy/rule/<pillar>/` package, return a complete `RuleDefinition`, register it in `RuleRegistry.defaults()`, and cover thresholds/metadata/severity with a focused test under `tests/unit/rule/`. Add or update a CLI integration assertion when the new rule changes report shape, exit-code behaviour, or output ordering.
