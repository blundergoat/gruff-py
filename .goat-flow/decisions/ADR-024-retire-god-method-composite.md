# ADR-024: Retire the `design.god-method` composite finding

**Status:** Accepted
**Date:** 2026-05-31
**Ticket/Context:** Supersedes [ADR-016](ADR-016-composite-finding-fingerprint-inputs.md) (composite fingerprint inputs); applies the cross-port DESIGN-PRINCIPLES P5 position ("Score correlated findings as one root-cause cluster") and its note that the `design.god-*` composite is being retired family-wide. Mirrors the touch-point discipline of the `complexity.npath` removal ([ADR-021](ADR-021-reviewability-profile.md)).

## Decision

The synthesised `design.god-method` finding is retired. Concretely:

- `src/gruffpy/scoring/composite_finding_factory.py` (`CompositeFindingFactory`) and its unit test `tests/unit/scoring/test_composite_finding_factory.py` are deleted.
- `src/gruffpy/analysis/runner.py` no longer calls `CompositeFindingFactory().synthesise(...)` in `_collect_findings`, and no longer seeds `design.god-method` into the suppression parser's `known_rule_ids` in `_parse_suppressions`. The second, now-redundant `apply_suppressions` pass (which existed only to let a synthesised composite be suppressed) is removed; one suppression pass over the real findings remains.
- `design.god-method` is removed from `CORRELATED_COMPLEXITY_RULES` in `src/gruffpy/scoring/score_calculator.py`. The five real contributors stay in the set — `complexity.cognitive`, `complexity.cyclomatic`, `complexity.nesting-depth`, `size.function-length`, `size.parameter-count` — so P5 clustering survives intact.

The `design` pillar stays non-empty: `design.single-implementor-protocol` remains its registered rule.

## Context

`design.god-method` was a *synthesised* finding: `CompositeFindingFactory` grouped per-unit findings by `(file, symbol)` and emitted one composite when at least one `size.*` and one `complexity.*` finding co-occurred on a symbol. Its only correct score was *neutral* — it was already a member of `CORRELATED_COMPLEXITY_RULES`, so it joined the same `(file, symbol, line)` cluster as its contributors and shared the `max(penalty) / len(cluster)` weight rather than adding a fresh penalty.

That makes it clustering logic wearing a finding's clothes. It fired only on the conjunction of findings that already cluster; it named no defect a reviewer could act on independently of the contributors the detailed report already lists; and because it carried `Pillar.DESIGN`, it diverted a slice of the cluster's penalty into the `design` pillar, making `design` look worse for a function whose actual smells are size and complexity. Under the forcing-function premise (a finding is a rewrite command to the agent), a synthetic "god method" finding points at no fix the underlying `size.*`/`complexity.*` findings don't already point at.

gruff-py already implements P5 the right way: `ScoreCalculator` clusters correlated `size.*`/`complexity.*` findings on one symbol into a single `max/len` penalty (the mechanism ADR-016 described as already present). Removing the composite leaves that mechanism as the sole P5 path. The one thing lost is the *named* "god-method" signal; every contributing finding remains visible in the detailed report.

This is the family-wide direction: gruff-rs has already removed its composite, and gruff-go/gruff-ts/gruff-php are retiring `design.god-function`/`design.god-method` in turn. gruff-py's `CORRELATED_COMPLEXITY_RULES` clustering is the reference pattern those ports are converging on.

## What is preserved

- **Schemas** `gruff-py.analysis.v1`, `gruff-py.baseline.v1`, `gruff-py.hotspot.v1` — unchanged.
- **Fingerprints** — the `fingerprint_for(...)` / `stable_identity_for(...)` algorithms and their gruff-php byte-compatibility are untouched. The composite was the only finding ADR-016 mapped onto that algorithm; removing it changes no input for any remaining finding. `tests/unit/finding/test_fingerprint.py` carried no `design.god-method` case, so nothing there changes.
- **Rule catalogue** — `design.god-method` was synthesised, never registered in `RuleRegistry.defaults()`. It never appeared in `list-rules`, `docs/rules.md`, or any rule count. The catalogue stays at 114 rules across 11 pillars (`design` stays at 1). This is the key contrast with the `complexity.npath` clean break, which *was* a catalogue rule and did move the counts and config `selection`.
- **Config** — `design.god-method` was never selectable or configurable; it is absent from `.gruff-py.yaml`. No `selection`/`rules` migration is required, and no config fails closed on its account.

## Breaking surface and migration

- **Stale suppression directives.** `# gruff: disable=design.god-method` (or `disable-file`/`disable-next`) no longer resolves: `design.god-method` is no longer in the suppression parser's `known_rule_ids`, so such a directive now emits a non-fatal `suppression-unknown-rule` diagnostic ("Unknown gruff rule id ...") and suppresses nothing. It is not a hard error and does not change exit codes. Migration: delete the directive — the composite it targeted is no longer emitted.
- **Stale baselines.** A baseline pinning a `design.god-method` fingerprint keeps that entry, but the finding is never emitted again, so the entry is inert (it suppresses nothing and never matches). Migration: regenerate the baseline after upgrading.

## Consequences

- Per-pillar penalty *distribution* shifts for a god-function: the `design` pillar no longer receives the synthetic slice (it drops to zero for that symbol), and the real `size.*`/`complexity.*` pillars absorb the full clustered weight. The **composite score is unchanged** because the cluster's total penalty is conserved — only its pillar attribution moves off `design`. This is verified by `tests/unit/scoring/test_score_calculator.py`.
- `CompositeFindingFactory` is gone; there is no remaining composite-synthesis seam. A future composite rule would reintroduce one deliberately rather than inherit this scaffold.
- ADR-016 is superseded; its fingerprint-input mapping applied only to this composite.

## Reversibility

Reversible in code (re-add the factory and the rule id to `CORRELATED_COMPLEXITY_RULES`), but the cross-port direction is to standardise on clustering, so reversal is not expected. No one-way-door compatibility constraint applies: the fingerprint algorithm and all schemas are untouched, so the only revisit triggers are a family-level decision to restore a named god-method signal, or a contributor-rule set change that the clustering set must track.
