# ADR-013: SARIF renderer contract

**Status:** Accepted
**Date:** 2026-05-17
**Ticket/Context:** M14 SARIF implementation hardening and interoperability.

## Decision

`gruff-py analyse --format sarif` is a dedicated SARIF 2.1.0 renderer over the
native `AnalysisReport`, `Finding`, and `RuleRegistry` models. It must not
change native report schemas, rule ids, finding fingerprint inputs, baseline
identity, scoring, fail-on behaviour, or rule semantics.

The SARIF contract is:

- `runs[0].tool.driver.name` is `gruff-py`.
- `runs[0].tool.driver.semanticVersion` uses the run's project version.
- `runs[0].tool.driver.rules` is built from `RuleRegistry.defaults()` and
  sorted by stable rule id for deterministic diffs.
- Results preserve the native finding rule id, message, severity, path,
  location, metadata, and fingerprint.
- Result fingerprints use `partialFingerprints.gruffFingerprint`.
- Run properties expose the native schema string as `gruffSchemaVersion`, plus
  score and grade when present.
- Artifact URIs use `/` and do not start with `./`.
- Unknown future or external rule ids get fallback driver-rule descriptors with
  the same top-level shape as registry-backed descriptors.
- SARIF `fixes`, `codeFlows`, `threadFlows`, suppression state, and baseline
  state stay absent until native gruff-py data supports them.

Two gruff-py differences from the current `gruff-rs` renderer are intentional:

- gruff-py sorts SARIF driver rules by rule id; gruff-rs currently emits
  registry definition order.
- gruff-py does not emit SARIF `properties.generatedAt` or driver-rule
  `properties.kind` until those values exist in the native gruff-py report or
  rule metadata model.

## Context

`gruff-rs` ADR-006 establishes the shared direction: report renderers preserve
the native analysis schema and adapt it into consumer formats. M10 added the
initial gruff-py SARIF output, and M14 hardens it for code-scanning consumers.

The non-obvious risks are contract drift and schema leakage: a renderer can
accidentally rename fingerprint keys, invent native schema names, expose stale
placeholder URLs, or add SARIF-only concepts to the native report model. Those
changes would make SARIF look healthier while breaking compatibility for JSON,
baselines, or cross-implementation consumers.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Reuse native JSON as SARIF-like output | Code-scanning tools cannot ingest it as SARIF. | Rejected; SARIF needs a real SARIF mapping. |
| Add SARIF-only fields to `gruff-py.analysis.v1` | Native JSON consumers inherit renderer churn and fingerprint risks. | Rejected; renderers adapt existing native data. |
| Render SARIF from `AnalysisReport` and `RuleRegistry` only | Some rich SARIF fields are unavailable until native data exists. | Accepted; it preserves native contracts and keeps output deterministic. |
| Mirror gruff-rs rule order exactly | gruff-py loses stable sorted diffs and simple `ruleIndex` tests. | Rejected for gruff-py; sorted rule ids are an intentional renderer-policy divergence. |
| Emit `generatedAt` or `kind` without native gruff-py fields | SARIF invents data that cannot be traced back to the native report. | Rejected until native models support those fields. |

## Reversibility

The renderer remains reversible as long as native report schemas and finding
fingerprints stay unchanged. Changing SARIF key names, rule ordering, or
metadata projection after consumers rely on them requires a compatibility note,
contract tests, and a migration plan.
