# ADR-009: Rule profiles and confidence filtering

**Status:** Proposed
**Date:** 2026-05-16
**Related:** ADR-021 supplies the first concrete profile (`reviewability`) and the agent-hook severity policy that motivates this preset layer.
**Ticket/Context:** M13 found useful profile/strictness models in Prospector and
Pyright, and confidence filtering models in Pylint and Vulture. Gruff already
stores finding confidence, but does not expose confidence filtering or named
strictness presets.

## Decision

Gruff should eventually add a small preset layer and confidence filter, but not a
full profile inheritance system.

Proposed shape:

- Named presets such as `default`/`balanced`/`strict` define rule enablement,
  severity overrides, and possibly confidence thresholds.
- Exact rule configuration always wins over a preset.
- Confidence filtering excludes findings below a configured confidence floor at
  report time; included findings keep the existing JSON/SARIF shape.
- Presets must be represented as deterministic data and tested as a rule matrix.

## Context

Prospector shows the value of profiles but also the complexity of inheritance and
tool aggregation. Pyright's off/basic/standard/strict diagnostic rule sets are a
better fit: named defaults plus explicit rule overrides. Vulture's
`--min-confidence` model is easy to explain and maps to gruff's existing
`Confidence` enum.

Profiles change the default analysis experience and are a public config contract.
They should land only after rule metadata, docs, and central suppression are
stable.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Small preset matrix plus exact overrides | Adds config surface and cross-implementation obligations. | Proposed: useful for noisy docs/test/dead-code calibration without hiding rules permanently. |
| Full Prospector-style profile inheritance | Complex precedence, external profile packages, and hard-to-debug behavior. | Rejected for v0.1.x/v0.2 foundation. |
| Confidence filtering only | Helps report noise but does not solve strict/default rule selection. | Partial: useful, but not enough by itself. |
| Keep one default forever | Forces every user into the same strictness/noise tradeoff. | Rejected: dogfood calibration already shows different rule families need different defaults. |

## Reversibility

Two-way door before the config is documented. Once presets are public, changes to
their defaults must be treated like compatibility-sensitive behavior changes and
coordinated with gruff-php/gruff-ts.
