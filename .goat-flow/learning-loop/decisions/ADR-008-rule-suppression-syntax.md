# ADR-008: Rule suppression syntax

**Status:** Proposed
**Date:** 2026-05-16
**Ticket/Context:** M13 related-project study found that Pylint, Flake8, mypy,
and Vulture all need precise suppression controls. Gruff currently has ad hoc
`# noqa` handling in a few rules, which cannot scale without inconsistent
behavior.

## Decision

Gruff should add one central suppression parser before broadening noisy or
dead-code rules.

Proposed syntax:

- `# gruff: disable=<rule-id>[,<rule-id>]` suppresses matching findings on the
  same line.
- `# gruff: disable-next=<rule-id>[,<rule-id>]` suppresses matching findings on
  the next physical source line.
- `# gruff: disable-file=<rule-id>[,<rule-id>]` suppresses matching findings for
  the file.

The first version should require explicit gruff rule ids. It should not introduce
block-level enable/disable semantics, wildcard groups, or global `# noqa`
normalization.

Suppression should be applied after rule execution as a central finding filter so
individual rules do not each parse comments. Unsuppressed finding payloads and
fingerprints must remain unchanged.

## Context

M13.2 identified suppression as a registry/config boundary. M13.4 reinforced the
need: Vulture supports `noqa` and whitelists, while mypy recommends
code-specific ignores so unrelated findings are not hidden.

This is a public behavior contract. gruff-php and gruff-ts will need the same
syntax if users expect shared `.gruff.yaml` and source comments to behave
consistently.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Central `# gruff:` suppression with explicit rule ids | Adds public syntax that cross-implementations must honor. | Proposed: precise, testable, and avoids rule-by-rule comment parsing. |
| Reuse global `# noqa` everywhere | Hides unrelated tools' intent and creates ambiguity between Ruff/Flake8/gruff. | Rejected: compatibility comments should not silently suppress gruff findings unless explicitly designed. |
| Per-rule ad hoc suppression | Each rule drifts in syntax, line matching, and tests. | Rejected: this is the current failure mode. |
| Pylint-style block disable/enable | More expressive, but much harder to implement and explain. | Deferred: no current gruff use case requires block-state semantics. |

## Reversibility

Two-way door before release. After shipping, syntax changes require a coordinated
cross-implementation migration because source comments become user-facing
configuration.
