# ADR-025: Project Rule Scope Honesty

**Status:** Accepted
**Date:** 2026-06-10
**Updated:** 2026-07-12

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

Absence-based module conclusions require stronger evidence than positive
reference findings. `dead-code.unused-private-function` therefore follows this
scope contract:

- A full-project scan may report a module-level private function only after the
  scanned import index finds no proven later load of an unambiguously resolved
  binding. The import declaration itself and bare re-export plumbing are not use.
- A partial or single-file scan suppresses module-level findings entirely because
  callers outside the requested paths are invisible. The run-level caveat still
  discloses that project-rule context is incomplete.
- Private methods retain their enclosing-class analysis in every scan scope;
  cross-module import resolution does not apply to them.
- A loaded import that resolves to multiple scanned modules suppresses nothing.
  The affected full-project finding remains at LOW confidence and records
  `scanScope=full-project` plus
  `externalReferenceCoverage=ambiguous`. A complete unreferenced conclusion
  remains MEDIUM confidence with `externalReferenceCoverage=complete`.

The additive metadata keys are provisionally registered in workspace
`FAMILY-CONTRACT.md` §4. No partial-scope metadata variant is emitted because
the corresponding module-level finding is absent. `gruff.hook.v1` payload and
exit semantics remain unchanged; successful hook analysis continues to exit 0.

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

The same evidence asymmetry affects private module functions. A real consumer
incident imported `_format_failed_emails` from another scanned module and stored
it in a registry, but the per-file rule still called the function unused. Moving
that rule to project dispatch fixes positive liveness only when the scanned
module and later load resolve uniquely; it does not infer dynamic plugin calls.

This partial-scan suppression decision supersedes the older caveat-retaining
outcome in
`.goat-flow/logs/critiques/2026-07-11-0635-gruff-py-upstream-handoff-e70b8.md`
(search: `F3: accepted with refinement`). That critique remains unchanged as
historical evidence; the later decision avoids asking users to remove code when
the scan cannot see all potential callers.

ADR-022 requires scope honesty for heuristic static analysis. The rule can stay
useful if it reports from the evidence it has and tells callers when project
context may be partial.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep the rule unchanged | Value-position protocol usage is missed and narrow runs have no scope warning. | Rejected. The rule remains noisy and silently scope-dependent. |
| Retire the rule | The design pillar loses its only real project-rule signal even though the rule is advisory and cheap. | Rejected for now. Retirement remains available if fixed output still proves untrustworthy. |
| Fix value-reference collection and add narrow-run caveats | Adds small metadata/reporting surface but keeps an actionable advisory signal. | Accepted. This is the smallest change that restores reviewer trust without deleting useful guidance. |
| Keep caveated private-function findings on partial scans | A warning can direct a user to delete a function whose external caller was outside the scan. | Rejected. Absence is not proved from partial evidence. |
| Count every import as private-function use | Unused imports and bare re-exports hide genuinely dead functions. | Rejected. A later load is required. |
| Resolve only one configured source-root layout | Flat, src, and monorepo layouts produce inconsistent liveness results. | Rejected. Exact relative paths and unique scanned-path suffixes are deterministic without a fixed root. |
| Suppress module findings on partial scans and require a unique loaded binding on full scans | Some unresolved dynamic uses still need the existing allowlist, but static evidence cannot silently hide a finding. | Accepted. It favors false-negative avoidance only when liveness is positively proved. |

## Consequences

- Project-rule output becomes more precise for real abstraction usage.
- Narrow analysis runs disclose that project-rule conclusions may be based on
  partial context.
- Future project rules must either be scope-local by construction or participate
  in the same partial-context caveat.
- Module-level private-function findings are suppressed on partial scans, while
  private-method checks remain available to users scanning one file.
- Full-project findings disclose whether scanned external-reference coverage was
  complete or ambiguous without changing their fingerprints or stable identities.

## Reversibility

Two-way door. If dogfood or adopter reports show the fixed rule is still
untrustworthy, remove it using the existing catalogue-rule retirement precedent:
deregister the rule, delete its tests and config/docs entries, regenerate the
catalogue docs, and record the breaking migration note.
