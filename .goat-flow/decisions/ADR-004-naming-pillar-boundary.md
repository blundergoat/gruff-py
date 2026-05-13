# ADR-004: Naming pillar boundary — gruff vs ruff N-rules

**Status:** Accepted
**Date:** 2026-05-13
**Ticket/Context:** `.goat-flow/tasks/0.1/M05-naming-pillar-v0.1.md`; cross-impl parity with gruff-php's `src/Rule/Naming/`.

## Decision

gruff-py's naming pillar owns **intent and semantics** in identifier names. ruff's `N`-rule family owns **PEP 8 case/style**. The two layers are disjoint and complementary.

| Concern | Owner | Examples |
|---|---|---|
| CamelCase classes / snake_case functions / lowercase arguments | **ruff** `N801–N812` | `class my_class:` → `N801`; `def MyFunc:` → `N802` |
| Hungarian-notation type prefixes | **gruff** `naming.hungarian-notation` | `i_count`, `s_name`, `arr_items` |
| Placeholder / generic identifier values | **gruff** `naming.identifier-quality` | `temp`, `temp1`, `foo`, `bar`, `result1` |
| Boolean prefix on bool-returning fns | **gruff** `naming.boolean-prefix` | `is_valid()`, `has_x()`, `can_y()` |
| Vague standalone class names | **gruff** `naming.confusing-name` | `Handler`, `Util`, `Manager` (only as standalone) |
| Vague function names | **gruff** `naming.generic-function` | `process`, `handle`, `do` |
| Parameter name vs type-hint mismatch | **gruff** `naming.parameter-type-name` | `repo: Repository` should be `repository` |
| Single-letter variables outside common idioms | **gruff** `naming.short-variable` | `def f(x): return q` (q is suspicious; x is fine) |
| Module name vs single-class name mismatch | **gruff** `naming.module-name-mismatch` | `class UserService` in `users.py` (should be `user_service.py`) |
| Test-naming convention mixing | **gruff** `naming.test-naming-consistency` | `test_foo` + `testBar` + `TestBaz` in one file |

## Disjoint coverage

Each gruff naming rule MUST NOT fire on a `(file, line)` already flagged by an active `ruff N`-rule. The cumulative integration test `tests/integration/test_naming_disjoint_from_ruff.py` runs `ruff check --select N --output-format json` on a fixture and asserts no `(rule_id_root, file, line)` overlap with gruff naming findings.

## Context

ruff's `N` rules are a fast, well-maintained reimplementation of PEP 8 naming style. Duplicating them in gruff would produce noise, dilute the value of running both linters, and force gruff users to suppress findings ruff already covered. gruff-php made this decision early (see `gruff-php/src/Rule/Naming/`); gruff-py adopts the same boundary.

The intent-layer rules gruff owns require AST + semantic context that single-pass style checkers don't have:

- Identifier-quality needs a tokenizer that splits `temp1` / `result2` / `data42` numeric suffixes — `IdentifierTokenizer`.
- Parameter-type-name needs to read the type annotation and compare against the parameter name.
- Boolean-prefix needs to read return-type annotations.
- Module-name-mismatch needs filesystem + AST coordination.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **Intent (gruff) + style (ruff), disjoint** (accepted) | Users must run both linters to get full coverage; some configuration overhead. | Accepted: two focused linters > one bloated one. The CI integration test enforces the boundary. |
| Duplicate ruff N rules in gruff | Noise on every Python project that already runs ruff. | Rejected: degrades trust. |
| Replace ruff N (gruff owns style too) | gruff would need to maintain a CamelCase regex matrix that ruff has battle-tested for years. | Rejected: massive duplication, no payoff. |
| Skip the intent-layer rules entirely | Loses the differentiator that justifies gruff existing on Python. | Rejected: gruff's pitch is "the smells ruff doesn't catch". |

## Consequences

- Adding any new naming rule requires checking it doesn't overlap with `ruff N`. The CI test enforces this — when ruff adds a new `N` rule that overlaps with gruff, gruff must back off or refactor.
- Users who run gruff without ruff will miss PEP 8 style violations. The CLI / docs make this clear ("complementary to ruff N").
- `naming.module-name-mismatch` and `naming.test-naming-consistency` are project-scope rules: they need filesystem context, not just AST.

## Reversibility

**Two-way door.** Removing the disjoint constraint and absorbing ruff-style rules is a one-PR change at any time. Removing the intent-layer rules entirely is also possible but loses the differentiator.

Revisit triggers:
- ruff drops naming-related N rules → gruff may need to absorb them.
- A consumer asks for a single-tool "no extra ruff config needed" path → consider duplicating with a `gruff.style.*` namespace.
