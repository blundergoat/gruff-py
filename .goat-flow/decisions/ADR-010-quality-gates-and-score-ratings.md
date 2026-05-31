# ADR-010: Quality gates and score ratings

**Status:** Proposed (2026-05-16); superseded in part by the 2026-06-01 addendum
below — composite/pillar score gates dropped, gating folds into M04's new-findings
gate.
**Date:** 2026-05-16
**Ticket/Context:** M13.1 found that SonarQube separates raw findings, scores,
ratings, and quality gates. Gruff currently has numeric scores and `--fail-on`,
but no explicit post-analysis gate model.

## Decision

Gruff should add quality gates as a v0.2 post-analysis layer. A quality gate
consumes an analysis result and returns OK/ERROR based on configured conditions.

The gate layer must stay separate from:

- `ScoreCalculator`, which computes numeric scores;
- `--fail-on`, which exits based on finding severity;
- finding fingerprints and `gruff-py.analysis.v1`, which should not change just
  because a gate is evaluated.

Score/rating bands may be added for aggregate and pillar scores, but any formula
or threshold change must be documented before implementation.

## Context

SonarQube's quality-gate model is useful because it makes policy explicit:
"fail if maintainability score is below X" is different from "fail if any error
finding exists." M13 also found that gruff's own metrics need calibration before
thresholds or ratings are treated as policy.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Post-analysis gate evaluator | Adds config/CLI behavior but leaves findings stable. | Proposed: cleanly separates policy from detection. |
| Fold gates into `--fail-on` | Severity failure and score/count conditions become hard to explain. | Rejected: combines two distinct concepts. |
| Encode gate status in every finding | Pollutes the finding schema and fingerprints with run-level policy. | Rejected: gate status belongs to the analysis/report summary. |
| Add ratings before metric calibration | Creates authoritative-looking grades from weak thresholds. | Deferred: run dogfood metric calibration first. |

## Reversibility

Two-way door before gate config is public. Once a gate config shape is released,
changes need an ADR update and cross-implementation compatibility review.

## Addendum (2026-06-01): score gates dropped; gating folds into M04

A cross-port re-scan (gruff-go/-rs/-ts/-php) for this exact feature found that
**score-based quality gates are shipped by no implementation**:

- gruff-go (ADR-013) and gruff-ts (ADR-006) reject count *and* score gating on the
  "agents fix everything" mission gruff-py shares (ADR-022).
- gruff-rs shipped a count gate that "never consults the score model".
- gruff-php shipped a count gate but explicitly **deferred** `failureConditions.score`
  and `failureConditions.pillars` "pending demand."
- No port ships configurable rating bands; A-F at 90/80/70/60 is a stable cross-port
  surface.

The capability the family validated is the **new-findings gate** (gruff-rs
`scope: new`, gruff-php `newFindings`, both via `--fail-on-new`; gruff-go plans it) —
gruff-py's M04.

**Decision (revises the 2026-05-16 proposal):** gruff-py will NOT add composite or
pillar score-condition gates. The post-analysis gate need is met by M04's new-findings
gate (fail on findings classified *new*), composed with the existing
`--fail-on <severity>`. A-F score ratings stay as-is; no configurable bands. The
"post-analysis gate evaluator" row above is withdrawn for score conditions. If
human-CI "tolerate up to N" count gates are ever wanted, that is a separate decision
that must converge on an existing sibling shape (gruff-rs `gate:` or gruff-php
`failureConditions:`), not a third gruff-py spelling.
