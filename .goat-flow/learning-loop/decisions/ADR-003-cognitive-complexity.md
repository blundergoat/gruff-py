# ADR-003: Cognitive complexity algorithm

**Status:** Accepted
**Date:** 2026-05-13
**Ticket/Context:** `.goat-flow/tasks/0.1/M03-complexity-pillar-v0.1.md`; cross-impl parity with gruff-php's `complexity.cognitive`.

## Decision

gruff-py's `complexity.cognitive` rule implements the **SonarSource Cognitive Complexity v1.4** algorithm (G. Ann Campbell, "Cognitive Complexity: A new way of measuring understandability", 2018) with the following increment rules:

**B1 - Increment by 1 for each control-flow break.** Each of the following adds 1 to the cognitive score:

- `if`, `elif`, `else` (the `if`/`elif` itself increments once; `else` increments once if present)
- `for`, `while`
- `try` and each `except` handler (one increment per handler)
- ternary expressions (`x if cond else y`)
- `match` statement (one increment for the `match`; each `case` does **not** add an extra B1 increment - handled by B2 nesting)
- recursion (a function calling itself by name) - one increment per call site

**B2 - Increment by `nesting_level` for each nested control structure.** When any control structure listed above is nested inside another, add the *current* nesting level on top of its B1 increment. Nesting only counts inside structures that themselves added a B1 increment (the SonarSource "structural increment" definition).

Nesting starts at 0 inside a function body. Each entry into a control structure (`if`/`for`/`while`/`try`/`except`/`match`) increments nesting by 1 for its body's scope. Function definitions inside a function reset nesting back to 0 for the inner function.

**B3 - Increment by 1 for each sequence of binary boolean operators.** A run of `and`/`or` operators of the same kind in a single expression adds 1 (not one per operator). Changing operator (e.g. `a and b or c`) increments again. `not` does not contribute.

**No increment for:** `pass`, `return`, `yield`, simple assignments, attribute access, function-definition lines themselves, decorators, comprehensions are treated like their underlying control structures (each `for` clause increments B1; each `if` clause increments B1; nesting from the comprehension scope counts).

## Context

Cognitive complexity addresses the gap between *cyclomatic* complexity (per-path branching count) and the felt difficulty a human reader experiences when nesting deepens. SonarSource v1.4 is the canonical reference; bandit/ruff/radon do not implement cognitive complexity natively. gruff-php's `complexity.cognitive` mirrors v1.4 byte-for-byte; gruff-py must do the same to keep `gruff-py.analysis.v1` JSON byte-equivalent.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **SonarSource v1.4** (accepted) | Boolean-operator-sequence rule (B3) is subtle and easy to get wrong on chained mixed operators. | Accepted: canonical reference; matches gruff-php. The B3 subtlety is captured in fixture tests. |
| Cyclomatic-as-cognitive | Trivial to implement but conflates two distinct metrics; users would lose the separate signal from `complexity.cyclomatic`. | Rejected: collapses two pillar signals into one. |
| McCabe's "essential complexity" | Closer to structural difficulty but not widely understood; no peer linter implements it. | Rejected: low ecosystem support. |
| SonarSource v1.5+ (later versions) | Tweaks around exception handling and async; not yet adopted by gruff-php. | Rejected for v0.1; revisit when gruff-php upgrades. |

## Consequences

- Increment table is part of the cross-impl contract. Any change requires a coordinated edit on gruff-php side and a baseline migration.
- The cognitive computation runs per `FunctionDef`/`AsyncFunctionDef`/`Lambda` AST node. Module-level code is not scored.
- Lambdas treated as single-expression functions: per ADR-003 §Lambda, the lambda body is evaluated as if it were a function body of one expression - comprehensions and boolean operators inside the lambda contribute B1/B3 normally; B2 nesting reset on entry to the lambda.

## Reversibility

**One-way door inside v0.1**, same compatibility constraint as ADR-002: changing the increment rules invalidates every cross-impl baseline.

Revisit trigger: SonarSource publishes v1.5+ AND gruff-php upgrades; coordinate the move on both sides.
