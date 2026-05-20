# ADR-016: Composite finding fingerprint inputs

**Status:** Accepted
**Date:** 2026-05-13
**Ticket/Context:** `.goat-flow/tasks/0.1/M03-complexity-pillar-v0.1.md` (`design.god-method`); cross-impl parity with gruff-php's `Scoring/CompositeFindingFactory`; `.goat-flow/footguns/compatibility.md` "Finding fingerprints depend on PHP-style JSON bytes".

## Decision

A **composite finding** synthesized by `CompositeFindingFactory` is a `Finding` like any other and is fingerprinted by the existing `fingerprint_for(...)` algorithm in `src/gruffpy/finding/fingerprint.py`. The fields fed into the fingerprint are exactly the same as for per-unit findings — `(ruleId, file, line, endLine, column, symbol)` — encoded with PHP-style slash escaping before SHA-256, truncated to 16 hex characters.

For `design.god-method` specifically:

- **`ruleId`**: literal `"design.god-method"`.
- **`file`**: the `file_path` of the symbol the composite covers (same value as on the contributing per-unit findings).
- **`symbol`**: the qualified name of the symbol (e.g. `"Outer.method_b"`), identical to the qualified name on contributing findings (`size.function-length`, `complexity.cyclomatic`, etc.).
- **`line`**: the **smallest** `line` among the contributing findings (the entry line of the composite finding into the file).
- **`endLine`**: the **largest** `endLine` among contributing findings.
- **`column`**: `None` (composite findings are symbol-scoped; column information is lost in synthesis).

Additionally, the composite finding's `metadata.componentRules` MUST be a **sorted tuple** of contributing rule IDs. The sort key is the rule ID string in ASCII order; ties broken by insertion order (impossible in practice because rule IDs are unique). The `secondaryPillars` of a composite are the **sorted set** of pillars of contributing findings, excluding the primary pillar (`design` for `design.god-method`).

The `message` template for `design.god-method` is:

```
Symbol '<symbol>' is a god method: <N> overlapping size/complexity findings on <file>:<line>.
```

where `<N>` is `len(componentRules)`. The message is NOT part of the fingerprint (the fingerprint algorithm excludes `message`), but it IS part of the dedupe key in `RuleRegistry._deduplicate` — and must match gruff-php's template byte-for-byte. (See `gruff-php/src/Scoring/CompositeFindingFactory.php::messageFor()` for the reference template; gruff-py replicates the exact `printf`-style output.)

## Context

`design.god-method` is a *synthesised* finding emitted by `CompositeFindingFactory` after per-unit rules run. The factory groups per-unit findings by `(file_path, symbol)` and emits a composite when at least one finding from each of {Size, Complexity} pillars co-occurs on the same symbol.

Without a locked fingerprint policy, the order of contributing rule IDs in `metadata.componentRules`, the chosen `line`/`endLine`, or a divergent `message` template silently produce different fingerprints between gruff-py and gruff-php. That breaks every cross-impl baseline (per `.goat-flow/footguns/compatibility.md`).

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **Lock fingerprint inputs exactly as above** (accepted) | Couples composite to the per-unit fingerprint algorithm; any change in `fingerprint_for(...)` propagates to composites. | Accepted: that coupling is correct — composites ARE findings, so they MUST share the algorithm. |
| Use a separate fingerprint algorithm for composites | Doubles the cross-impl surface area; gruff-php and gruff-py have to maintain two algorithms in lockstep. | Rejected: needlessly increases drift risk. |
| Hash the contributing findings' fingerprints | Order-dependent; would require sorting fingerprints; gruff-php does not do this. | Rejected: diverges from gruff-php. |
| Skip fingerprinting composites | Breaks baseline diff for `design.god-method`; user can never suppress a specific composite. | Rejected: composites must be baseline-suppressible like any finding. |

## Consequences

- Any change to the composite `message` template requires a coordinated gruff-py + gruff-php edit AND a baseline migration.
- The factory MUST sort `componentRules` before serialisation; tests assert this.
- `tests/unit/finding/test_fingerprint.py` adds a `PHP_GROUND_TRUTH` case for `design.god-method` covering at least one fixture with mixed Size + Complexity contributors.

## Reversibility

**One-way door**, same compatibility constraint as ADR-002 and ADR-003. Revisit triggers:

- gruff-php changes its `CompositeFindingFactory::messageFor()` template — coordinate the same change on gruff-py side and bump the baseline schema.
- The `fingerprint_for(...)` algorithm changes — propagate through composites.
