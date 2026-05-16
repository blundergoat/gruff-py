# ADR-011: Finding metadata extensions

**Status:** Proposed
**Date:** 2026-05-16
**Ticket/Context:** M13.1 and M13.3 identified useful metadata from SonarQube,
Bandit, Semgrep, and CodeQL: remediation effort, CWE/OWASP tags, security
severity, confidence rationale, and source/sink labels.

## Decision

Gruff should extend rule documentation and finding metadata incrementally, not
replace the core finding schema.

Proposed order:

1. Add rule-definition documentation fields: rationale, fix guidance, examples,
   formula provenance, and confidence rationale.
2. Add security taxonomy metadata for security/sensitive-data rules where mapping
   is clear: CWE, OWASP, security severity, and references.
3. Add lightweight source/sink labels for bounded security rules.
4. Defer remediation effort estimates and full dataflow traces until a separate
   schema review.

Finding fingerprints must not include optional metadata fields unless a future
ADR explicitly changes fingerprint inputs.

## Context

Bandit exposes severity/confidence and CWE details. Semgrep and CodeQL include
security metadata and source/sink concepts. SonarQube uses remediation/debt
metadata for prioritization. These are valuable for reports, but they create
schema and cross-implementation pressure.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Add optional metadata under existing finding metadata | Reporters must handle absent fields. | Proposed: useful without breaking `gruff.analysis.v1`. |
| Add top-level required fields for security/remediation | Non-security rules get meaningless fields; schema migration required. | Rejected for v0.1.x/v0.2 foundation. |
| Add full dataflow traces now | Requires source/sink path schema and stronger analysis engine. | Rejected for current scope. |
| Keep metadata out of findings forever | SARIF/reporting lose useful security context. | Rejected: related tools show this context is valuable. |

## Reversibility

Mostly two-way while fields remain optional metadata. Required schema fields or
fingerprint-input changes are one-way doors and require a separate accepted ADR.
