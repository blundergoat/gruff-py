# ADR-002: Size line-counting policy

**Status:** Accepted
**Date:** 2026-05-13
**Updated:** 2026-10-09
**Ticket/Context:** 0.1 size-pillar delivery; cross-impl parity with gruff-php M05.

> **Amendment (2026-08-08) — `size.file-length` counts substantive lines.** The gruff family ratified substantive-line counting for file length on 2026-08-05, and every port shipped it: gruff-php added `src/Rules/Size/SubstantiveLineCounter.php`, and gruff-go, gruff-rs, and gruff-ts each record "file-length: 1000 substantive lines at error (family ratification)" in their changelogs. gruff-py's `size.file-length` therefore counts substantive lines — blank lines, full-line `#` comments, and PEP 257 docstrings are free, while strings outside docstring positions still count. This satisfies the coordinated-sibling-change condition in Reversibility below; it is family convergence, not gruff-py drift.
>
> Scope of the amendment: **`size.file-length` only.** Every other size rule, the `complexity.maintainability-index` LOC term, and the test-length rules still consume raw `lines_for_size(...)` spans exactly as ratified above. Baselines are unaffected: `fingerprint` hashes `[ruleId, file, line, endLine, column, symbol]`, the finding stays anchored at line 1, and `end_line` still reports `unit.line_count()`, so only the `metadata.lines` measurement changed. Because substantive counts are never greater than raw counts, the change can only remove findings, never add them.

> **Amendment (2026-10-09) - every size count is code lines.** The gruff family ratified code lines for every line count a rule compares with a threshold (FAMILY-CONTRACT.md section 12, search "Code lines in every line count"). `lines_for_size(...)` therefore counts code lines, with blank lines, comment-only lines, PEP 257 docstrings and decorator lines free, for every size rule (`size.function-length`, `size.class-length`, `size.average-function-length` and `size.file-length`), the `complexity.maintainability-index` lines term, and the test-length rules (`test-quality.setup-bloat`, `test-quality.test-function-too-long` and `test-quality.test-longer-than-sut`). For `size.file-length` the only new free lines are decorator lines; the 2026-08-08 policy already freed the rest. This supersedes the `size.file-length`-only scope of the 2026-08-08 amendment and the "Docstrings count" clause of the Decision below. Thresholds are unchanged; a finding's `metadata.lines` reports the code-line count.

> **Amendment (2026-10-09, precision-floor M14) - function length counts logical lines.** FAMILY-CONTRACT.md section 12 (search "Measures that stop counting data or syntax as logic") makes `size.function-length` the one exception to the shared code-line count: it counts logical lines, the statements and compound-statement headers the tokenizer ends with NEWLINE, through `logical_line_numbers(...)` and `logical_lines_for_size(...)` in `src/gruffpy/rule/size/_lines.py`. A multi-line literal, a call whose arguments span lines, and a signature that lists one parameter per line each count once; docstrings and decorators stay free. `metadata.lines` reports the logical count. Every other consumer named above keeps the code-line count (`lines_for_size(...)`, or the file's `code_line_numbers(...)` set for `size.file-length`), so the maintainability index still shares `lines_for_size(...)`, as the Decision requires. Thresholds are unchanged. A logical count is never greater than the code-line count, so the change can only remove findings or lower their measured value.

## Decision

The size pillar (M02) ships a single helper `lines_for_size(unit, node) -> int` that returns the **raw line span**, **decorator-line through `node.end_lineno`, inclusive**, for every Python AST node it scores. Specifically:

- For `ast.FunctionDef` / `ast.AsyncFunctionDef` / `ast.ClassDef`: count `(end_lineno - decorator_lineno + 1)` where `decorator_lineno` is the `lineno` of the first decorator if any, else the node's own `lineno`.
- For `ast.Lambda`: count `(end_lineno - lineno + 1)`. Lambdas may not be decorated.
- For module-level scope (`ast.Module`): count `unit.line_count()` (existing helper).
- **Docstrings count.** Blank lines count. Comment-only lines count. Multi-line signatures count from the `def`/`class` line through the closing line of the signature; this falls naturally out of `end_lineno`.

This helper is consumed by every M02 size rule that needs a length number. M03's `complexity.maintainability-index` LOC term and M09a's `test-function-too-long` / M09b's `test-longer-than-sut` MUST also consume this helper; they MUST NOT re-derive line counts locally.

## Context

gruff-php's size pillar (`src/Rule/Size/`) measures **raw line span** because that is the metric a human reader sees when they open a file in an editor: "this method is 70 lines long" includes docstring lines and blank-line breathing room. The cross-implementation contract (`gruff-py.analysis.v1`, finding fingerprints) means `metadata.lines` MUST be byte-equivalent across gruff-php and gruff-py for the same conceptual symbol; using a different counting policy would silently invalidate every cross-impl baseline.

Python's `ast` exposes `node.end_lineno` reliably on Python ≥3.8 (gruff-py's supported floor is 3.11). The decorator line is the `lineno` of the first decorator in `node.decorator_list` if present.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **Raw line span, decorator → end_lineno** (accepted) | Counts a function with a long docstring as "long" even when the executable body is tiny. | Accepted: matches gruff-php byte-for-byte; matches the metric a code reader sees; deterministic and AST-driven; no false negatives on long docstrings. |
| Logical lines (executable only) | Diverges from gruff-php; breaks `gruff-py.analysis.v1` JSON byte-equivalence for `metadata.lines`; makes the LOC term in M03's MI formula non-comparable with radon's LOC; requires a separate "raw" counter anyway for `size.file-length` (already shipped using raw). | Rejected: cross-impl contract violation. |
| Configurable per-rule | Helper signature complicates; users have to learn a knob; defers the decision into runtime config; risks per-rule drift. | Rejected: no real consumer asks for both modes in v0.1. |
| Source-text-scanning fallback (split on `\n`) | Bypasses the AST and double-counts continuations / line-continuation backslashes; loses decorator awareness. | Rejected: AST exposes everything we need; fallback is unnecessary on Python ≥3.8. |

## Consequences

- `size.file-length` continues to use `unit.line_count()` (whole-file `\n` count + 1); the new helper is for *symbol-scoped* counts. The two paths are intentionally separate because `file-length` measures the file as a whole, not an AST node.
- `metadata.lines` on every size finding equals what `lines_for_size()` returns; downstream consumers (`ScoreCalculator.fileScores().maxLines`, gruff-php fingerprint comparison) can rely on the single definition.
- M03 / M09a / M09b are coupled to this helper. If the helper signature changes, those milestones' rules must be updated together (single source of truth).

## Reversibility

**One-way door inside v0.1.** Reversing this decision after any size pillar v0.1 release breaks every cross-impl baseline byte-for-byte (per `.goat-flow/learning-loop/footguns/compatibility.md`). The decision can be revisited in v0.2 only with an explicit baseline migration path AND a coordinated gruff-php change.

Revisit triggers (any of):

- gruff-php switches its line-counting policy in a future major version.
- An incident shows that raw line span produces majority-false-positive findings on a realistic codebase that cannot be tuned away.
- A consumer rule (M03 MI, M09 test-length) requires a distinct LLOC metric that genuinely cannot share the helper; in that case add a parallel `loc_for_mi()` helper rather than replacing `lines_for_size()`.
