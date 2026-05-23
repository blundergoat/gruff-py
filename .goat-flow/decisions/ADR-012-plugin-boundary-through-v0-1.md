# ADR-012: Plugin boundary through v0.1

**Status:** Proposed
**Date:** 2026-05-16
**Ticket/Context:** M13.2 compared Ruff, Pylint, and Flake8 plugin/rule
architectures. M13.5 needs a durable answer for whether gruff should expose a
public third-party rule API during the v0.1.x cleanup work.

## Decision

Gruff should not expose a public third-party plugin API through v0.1.x.

Instead:

- keep the rule catalog first-party;
- replace the manual default registry with a built-in catalog or generated
  catalog check;
- add generated rule docs and metadata invariant tests;
- revisit plugins only after rule metadata, suppression, config precedence, and
  cross-implementation behavior are stable.

## Context

Ruff shows the value of a strong first-party catalog with generated metadata and
docs. Pylint and Flake8 show the long-term compatibility cost of public checker
and plugin APIs. Gruff still needs to stabilize rule definitions, config,
suppression, and gruff-php parity before it can support third-party rules.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| First-party catalog only through v0.1.x | Users cannot install arbitrary third-party rules yet. | Proposed: preserves velocity and compatibility while the core contract settles. |
| Flake8-style entry-point plugins | Plugin loading, options, and error-code conventions become public immediately. | Rejected for v0.1.x. |
| Pylint-style checker API | Powerful, but commits gruff to checker lifecycle and message APIs. | Rejected for current scope. |
| Semgrep-style external rule language | Incompatible with gruff's curated rule classes and cross-implementation model. | Rejected for current scope. |

## Reversibility

Two-way door. A public plugin API can be added later by a new ADR. Shipping a
plugin API too early is much harder to reverse because third-party rules become a
compatibility surface.
