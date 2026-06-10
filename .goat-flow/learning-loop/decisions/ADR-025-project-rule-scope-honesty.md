# ADR-025: Project Rule Scope Honesty

**Status:** Accepted
**Date:** 2026-06-10

## Decision

Keep `design.single-implementor-protocol` as an advisory project rule, but make
its evidence boundary explicit and fix its reference model.

The rule counts abstraction references in both annotations and value positions,
including `isinstance(...)` and `issubclass(...)` checks. It must not count the
abstraction's own class declaration, implementor base lists, or value references
to the concrete implementor as abstraction usage.

When any project rule is enabled and the requested analysis path is narrower
than the project root, analysis reports carry an additive partial-context caveat
and text output renders that caveat. The caveat is run metadata, not a finding,
and it must not change finding fingerprints, stable identities, score math, or
exit-code calculation.

## Context

`design.single-implementor-protocol` is currently the only registered
`ProjectRuleProtocol` rule. It is advisory and cheap under gruff-py's
path-scoped discovery model, so its cost profile does not match sibling cases
where project rules were retired for high latency and high false-positive rates.

Two defects made the rule less honest than the rest of the catalogue:

- It counted annotation references but missed value-position abstraction checks,
  so a protocol used in `isinstance(codec, CodecPort)` could still be reported
  as having no external usage.
- It can produce different results on a narrow path than on the whole project
  because implementors outside the requested path are invisible.

ADR-022 requires scope honesty for heuristic static analysis. The rule can stay
useful if it reports from the evidence it has and tells callers when project
context may be partial.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep the rule unchanged | Value-position protocol usage is missed and narrow runs have no scope warning. | Rejected. The rule remains noisy and silently scope-dependent. |
| Retire the rule | The design pillar loses its only real project-rule signal even though the rule is advisory and cheap. | Rejected for now. Retirement remains available if fixed output still proves untrustworthy. |
| Fix value-reference collection and add narrow-run caveats | Adds small metadata/reporting surface but keeps an actionable advisory signal. | Accepted. This is the smallest change that restores reviewer trust without deleting useful guidance. |

## Consequences

- Project-rule output becomes more precise for real abstraction usage.
- Narrow analysis runs disclose that project-rule conclusions may be based on
  partial context.
- Future project rules must either be scope-local by construction or participate
  in the same partial-context caveat.

## Reversibility

Two-way door. If dogfood or adopter reports show the fixed rule is still
untrustworthy, remove it using the existing catalogue-rule retirement precedent:
deregister the rule, delete its tests and config/docs entries, regenerate the
catalogue docs, and record the breaking migration note.
