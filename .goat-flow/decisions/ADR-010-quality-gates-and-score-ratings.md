# ADR-010: Quality gates and score ratings

**Status:** Proposed
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
