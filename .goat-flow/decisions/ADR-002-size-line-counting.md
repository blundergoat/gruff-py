# ADR-002: Size line-counting policy

**Status:** Accepted
**Date:** 2026-05-13
**Ticket/Context:** `.goat-flow/tasks/0.1/M02-size-pillar-v0.1.md`; cross-impl parity with gruff-php M05.

## Decision

The size pillar (M02) ships a single helper `lines_for_size(unit, node) -> int` that returns the **raw line span**, **decorator-line through `node.end_lineno`, inclusive**, for every Python AST node it scores. Specifically:

- For `ast.FunctionDef` / `ast.AsyncFunctionDef` / `ast.ClassDef`: count `(end_lineno - decorator_lineno + 1)` where `decorator_lineno` is the `lineno` of the first decorator if any, else the node's own `lineno`.
- For `ast.Lambda`: count `(end_lineno - lineno + 1)`. Lambdas may not be decorated.
- For module-level scope (`ast.Module`): count `unit.line_count()` (existing helper).
- **Docstrings count.** Blank lines count. Comment-only lines count. Multi-line signatures count from the `def`/`class` line through the closing line of the signature; this falls naturally out of `end_lineno`.

This helper is consumed by every M02 size rule that needs a length number. M03's `complexity.maintainability-index` LOC term and M09a's `test-function-too-long` / M09b's `test-longer-than-sut` MUST also consume this helper; they MUST NOT re-derive line counts locally.

## Context

gruff-php's size pillar (`src/Rule/Size/`) measures **raw line span** because that is the metric a human reader sees when they open a file in an editor: "this method is 70 lines long" includes docstring lines and blank-line breathing room. The cross-implementation contract (`gruff.analysis.v1`, finding fingerprints) means `metadata.lines` MUST be byte-equivalent across gruff-php and gruff-py for the same conceptual symbol; using a different counting policy would silently invalidate every cross-impl baseline.

Python's `ast` exposes `node.end_lineno` reliably on Python ≥3.8 (gruff-py's supported floor is 3.11). The decorator line is the `lineno` of the first decorator in `node.decorator_list` if present.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **Raw line span, decorator → end_lineno** (accepted) | Counts a function with a long docstring as "long" even when the executable body is tiny. | Accepted: matches gruff-php byte-for-byte; matches the metric a code reader sees; deterministic and AST-driven; no false negatives on long docstrings. |
| Logical lines (executable only) | Diverges from gruff-php; breaks `gruff.analysis.v1` JSON byte-equivalence for `metadata.lines`; makes the LOC term in M03's MI formula non-comparable with radon's LOC; requires a separate "raw" counter anyway for `size.file-length` (already shipped using raw). | Rejected: cross-impl contract violation. |
| Configurable per-rule | Helper signature complicates; users have to learn a knob; defers the decision into runtime config; risks per-rule drift. | Rejected: no real consumer asks for both modes in v0.1. |
| Source-text-scanning fallback (split on `\n`) | Bypasses the AST and double-counts continuations / line-continuation backslashes; loses decorator awareness. | Rejected: AST exposes everything we need; fallback is unnecessary on Python ≥3.8. |

## Consequences

- `size.file-length` continues to use `unit.line_count()` (whole-file `\n` count + 1); the new helper is for *symbol-scoped* counts. The two paths are intentionally separate because `file-length` measures the file as a whole, not an AST node.
- `metadata.lines` on every size finding equals what `lines_for_size()` returns; downstream consumers (`ScoreCalculator.fileScores().maxLines`, gruff-php fingerprint comparison) can rely on the single definition.
- M03 / M09a / M09b are coupled to this helper. If the helper signature changes, those milestones' rules must be updated together (single source of truth).

## Reversibility

**One-way door inside v0.1.** Reversing this decision after any size pillar v0.1 release breaks every cross-impl baseline byte-for-byte (per `.goat-flow/footguns/compatibility.md`). The decision can be revisited in v0.2 only with an explicit baseline migration path AND a coordinated gruff-php change.

Revisit triggers (any of):

- gruff-php switches its line-counting policy in a future major version.
- An incident shows that raw line span produces majority-false-positive findings on a realistic codebase that cannot be tuned away.
- A consumer rule (M03 MI, M09 test-length) requires a distinct LLOC metric that genuinely cannot share the helper; in that case add a parallel `loc_for_mi()` helper rather than replacing `lines_for_size()`.
