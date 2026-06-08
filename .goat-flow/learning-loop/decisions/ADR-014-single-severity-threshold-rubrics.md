# ADR-014: Single Severity Threshold Rubrics

**Status:** Implemented
**Date:** 2026-05-18
**Ticket/Context:** M22 rubric calibration; gruff-php parity check against
`gruff-php/src/Config/RuleSettings.php`,
`gruff-php/src/Config/RuleConfigApplier.php`, and `.gruff-php.yaml`; user
correction that rubrics should not be warning/error ranges.

## Decision

Every severity-bearing rubric has exactly one configured threshold value and
one configured severity.

For a rule whose numeric threshold directly determines finding severity, public
config must use:

```yaml
rules:
  complexity.cognitive:
    threshold: 30
    severity: error
```

Do not expose warning/error ranges for these rubrics in dogfood config, user
docs, generated rule docs, or calibration output. The active threshold is one
number; crossing it emits the configured severity.

The `thresholds` table remains valid only for rule-specific tuning knobs whose
names describe what is being tuned, not severity bands:

```yaml
rules:
  test-quality.eager-test:
    thresholds:
      maxAssertions: 5
```

Accepted named threshold keys include values such as `maxAssertions`,
`maxMocks`, `maxCycles`, `maxCasesWithoutIds`, `minGroupSize`,
`maxSetupLines`, and sensitive-data knobs such as `minLength` and `entropy`.
They must not be renamed to `warning` or `error` unless they are genuinely a
severity-bearing rubric.

## Context

gruff-py's older config repeated built-in `warning` and `error` thresholds in
`.gruff-py.yaml` and examples. That made rubric policy look like a range when
the intended user-facing policy is one threshold with one severity.

gruff-php already implements the desired split:

- `RuleSettings::highValueThresholdMatch()` and
  `RuleSettings::lowValueThresholdMatch()` use an optional
  `SeverityThreshold` when configured.
- `RuleConfigApplier` accepts `threshold` plus `severity` for rules with
  exactly warning/error metric defaults.
- The gruff-php dogfood config uses `threshold` plus `severity` for metric
  rubrics and keeps `thresholds` for named knobs such as
  `minPositionalArguments`.

gruff-py now mirrors that contract: `RuleSettings` has
`severity_threshold`, the loader accepts `threshold` plus `severity`, and
`.gruff-py.yaml` uses one value and one severity for each warning/error
rubric. Generated docs and `metric-calibration` output describe the single
active threshold rather than warning/error ranges.

## Contract

- `rules.<id>.threshold` is numeric and must be paired with
  `rules.<id>.severity`.
- `rules.<id>.severity` must be `warning` or `error`.
- `threshold` and `thresholds` must not appear in the same rule entry.
- `threshold` plus `severity` is valid only when the rule's built-in
  thresholds are exactly `warning` and `error`.
- For lower-is-worse metrics, such as maintainability index, the same single
  threshold contract applies; the rule decides whether crossing means `>` or
  `<`.
- Rules with semantic knobs must keep those knobs under `thresholds.<name>`.
  Loader validation should reject unknown named threshold keys.
- Built-in rule defaults may keep legacy warning/error values internally as
  fallback defaults, but public dogfood config and documentation must present
  one active threshold plus severity for severity-bearing rubrics.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Single `threshold` plus `severity` for severity-bearing rubrics | Requires loader support and docs updates; internal fallback defaults still need careful explanation. | Accepted: matches gruff-php, makes policy explicit, and avoids pretending users are configuring a warning/error range. |
| Public warning/error threshold ranges | Users have to infer which value is authoritative; docs and calibration output imply two policy levels for one rubric. | Rejected: this was the user-visible confusion this ADR resolves. |
| Put every numeric value under `threshold` | Multi-value knobs such as entropy detection and test-structure limits lose their semantic names. | Rejected: these are not severity rubrics; semantic names are clearer and safer. |
| Allow `threshold` without `severity` | The same threshold can silently inherit a default severity that users did not choose. | Rejected: public policy must state both the value and severity. |
| Allow `threshold` and `thresholds` together | Rule behavior becomes ambiguous when both a severity threshold and named overrides are present. | Rejected: the loader must reject mixed shape. |

## Consequences

- Config examples should show `threshold` plus `severity` for size,
  complexity, maintainability, docs TODO density, and test length rubrics.
- Generated rule docs should label these as `Config threshold`, not
  `Thresholds`.
- `metric-calibration` should emit one `threshold`, one `thresholdSeverity`,
  and one `thresholdCrossings` value per metric summary.
- Tests that validate `.gruff-py.yaml` against `RuleRegistry.defaults()` must
  treat warning/error built-in defaults as eligible for the single-threshold
  public config shape.
- New rules must decide whether their numeric value is a severity rubric or a
  named tuning knob before choosing config shape.

## Reversibility

This is reversible only through a coordinated cross-implementation decision.
Reintroducing warning/error ranges in public config would break the gruff-php
parity contract and recreate the ambiguity fixed here.

Revisit triggers:

- gruff-php changes its public threshold model;
- gruff adds severities beyond `warning` and `error` for configurable
  threshold crossings;
- a rule genuinely needs multiple severity thresholds as first-class user
  policy, in which case it needs a new ADR and cross-implementation review.
