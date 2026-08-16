# ADR-026: Route the family capability analysis to the 0.7.0 horizon

**Status:** Accepted
**Date:** 2026-08-09
**Ticket/Context:** 0.5.0 release closeout; preserves the 2026-07-11 family
capability analysis as durable evidence instead of widening a defect-only release.

## Context

On 2026-07-11 the workspace ran five parallel per-port capability inventories,
each verified against source (rule registries, scoring engines, config loaders,
hook contracts) rather than against documentation. Headline counts were go 83
rules (70 default-on), php 128, py 130, rs 85 (84 on), and ts 120. The gruff-py
inventory recorded 130 built-in rules across 12 active pillars, all at tier
`v0.1`, with a 63 HIGH / 62 MEDIUM / 5 LOW confidence spread.

The analysis surfaced real, verified divergence:

- **Scoring engines disagree.** gruff-py penalises 1/4/12 (advisory/warning/error)
  multiplied by confidence with a `100 - 4Σ` pillar formula and a five-rule
  cluster keyed on `(file, qualified symbol)` with the line deliberately dropped.
  Other ports use different weights, formulas, and cluster keys, yet every port
  shares the same letter thresholds. An "A" therefore does not mean the same
  thing across the family.
- **Rule IDs have drifted** for identical concepts: `sensitive-data.url-credentials`
  in php/py versus `url-embedded-credentials` in rs; `security.ssrf` in py versus
  `ssrf-candidate` in rs/ts versus `request-controlled-url` in go.
- **Rule gaps verified absent** from `src/gruffpy/rule/` on 2026-07-11: asyncio
  hygiene (un-awaited coroutines, unreferenced `create_task`, blocking calls in
  `async def`), the classic correctness idioms (mutable default arguments and
  `is` versus `==` on literals), resource cleanup without a context manager or
  `try`/`finally`, production duplication detection, and production magic numbers.

None of this is a reproduced 0.5.0 defect. The 0.5.0 release boundary is
explicitly limited to defects and reproducibility gaps reproduced against current
source, so acting on the analysis inside 0.5.0 would have broken that boundary.
The evidence still needed a durable home: the plans directory is gitignored, and
this decisions directory accepts ADRs only, so copying a raw inventory here would
violate its own README.

## Decision

The 2026-07-11 family capability analysis is recorded as **routed input to the
0.7.0 planning horizon**, not as 0.5.0 scope. Concretely:

1. **No capability-analysis rule gap is implemented in 0.5.0.** The six gap
   families above stay unimplemented for this release.
2. **Every recorded absence must be revalidated against `src/gruffpy/rule/`
   before activation.** The inventory is a 2026-07-11 snapshot, and later
   milestones have already changed the catalog; a stale absence must not be
   treated as a live gap.
3. **Scoring and severity parity is not carried by this record.** It belongs to
   the family contract's scoring-parity track and lands with the JSON break,
   because scores are serialized and changing them is a compatibility event.
4. **Only two items are early-pull candidates:** mutable default arguments and
   `is` versus `==` on literals, both near-zero-false-positive AST matches
   against a correctness pillar that holds just two rules today. Pulling either
   into a release before 0.7.0 requires explicit operator approval.
5. **The verified inventories stay in the workspace, referenced not copied.**
   Durable pointers are `plan-reviews-2026-07-11/family-capability-analysis.md`
   and `plan-reviews-2026-07-11/capability-inventory-py.md`, with the ratified
   routing, draft scoring parity, and draft rule-lifecycle tooling sections of
   the workspace `FAMILY-CONTRACT.md`.

This record does not activate any rule, engine, or tooling idea it names.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Route to 0.7.0 and keep the verified evidence addressable | Nothing ships now; the analysis must be revalidated before use | **Accepted.** Preserves verified work at its real confidence level, keeps the defect-only release boundary intact, and makes 0.7.0 planning start from evidence instead of re-derivation. |
| Implement the gaps inside 0.5.0 | Breaks the release's stated defect-only boundary; ships six rule families with no reproduced defect and no calibration corpus | Rejected. Release scope is a commitment, and new rules without calibration are how false-positive debt enters a catalog. |
| Copy the raw inventories into the decisions directory | The directory's README accepts ADRs only; a bare inventory is a stats failure and rots without a decision attached | Rejected. The durable artifact is the routing decision; the inventory is its evidence, referenced by path. |
| Discard the analysis and re-derive at 0.7.0 | Five verified per-port inventories are lost; the next pass repeats source verification and likely reaches different numbers | Rejected. The verification cost is real and the numbers are already source-checked. |
| Leave it only in the gitignored plans directory | Evidence disappears at checkout boundaries; a future agent cannot follow the pointer | Rejected. That is precisely why this ADR exists. |

## Reversibility

**Two-way door.** Nothing in the codebase changes as a result of this record, so
there is no rollback to perform — superseding it costs one ADR.

Revisit triggers:

- 0.7.0 planning opens and consumes these inputs as named work.
- An operator approves an early pull of either trivial correctness idiom.
- The family ratifies one scoring spec, which supersedes this record's
  deferral of the scoring-parity question.
- A capability-analysis gap is independently reproduced as a live defect, at
  which point it becomes ordinary release work and stops depending on this
  routing decision.
