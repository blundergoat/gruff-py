# ADR-029: Rules wrong more often than right are retired, not tuned

**Status:** Accepted
**Date:** 2026-10-05
**Author(s):** Claude, user direction
**Ticket/Context:** precision-floor M19 under family lock M82.

## Context

The 0.6.0 precision measurement evaluated finding accuracy across the rule catalogue. On 2026-10-04 the operator ruled that any rule with enough judged findings that is right less than half the time is deleted rather than tuned, and accepted the gruff-py retirement table with "Accept all (Recommended)". The same family decision is recorded in gruff-go ADR-021 and gruff-php ADR-034.

## Decision

gruff-py retires five rules the 0.6.0 precision measurement found right less than half the time:

- `dead-code.unused-private-function`, right on 3 of 25 judged findings;
- `security.django-mark-safe`, right on 7 of 37;
- `security.sql-concatenation`, right on 4 of 37;
- `sensitive-data.high-entropy-string`, right on 1 of 25, with the built-in lockfile skip that existed only for it
  (FAMILY-CONTRACT.md section 12 and section 13a now bind gruff-rs alone);
- `waste.unused-parameter`, right on 4 of 25.

Each rule's module goes, with the helpers only it used, its tests, its generated docs entry and its dogfood config
blocks, as ADR-018 retired `naming.parameter-type-name`. A `# gruff: disable=` comment, a `selection` list or a
`sensitiveExclusions` entry that names one exits 2; a `rules:` block that names one is ignored with a warning; `--include-rule`
and `--exclude-rule` accept one silently.

It also turns five rules off by default, each right less than half the time on fewer than ten findings, too few to
delete on: `security.django-raw-sql` (right on 2 of 5), `security.github-actions-secrets-in-pr` (wrong on its only
judged finding), `security.shell-injection` (right on 3 of 7), `sensitive-data.api-key-pattern` (wrong on all 5) and
`sensitive-data.url-credentials` (wrong on all 3). They stay in the catalogue and run when a config enables them.

The family specification records the retirements as a catalogue transition with no successor, and keeps each rule's
review record as `retired` (workspace ADR-010).

## M02 retirement pilot, 2026-10-17

The operator accepted M02's review amendment and M95 runtime scope, inherited by M102. Row py-006 retires `modernisation.f-string-candidate`: none of its 23 judged findings was right, and the observed conversions did not make formatting templates easier to verify. The source module, its eight direct detector tests, catalogue metadata and dogfood settings are removed. The same eight positive and negative source cases now exercise the default registry with the former rule explicitly enabled, proving it cannot emit. The other 124 native records are unchanged.

The workspace evidence is `.goat-flow/plans/0.6.0-precision-floor/evidence/m02/py-line/verification.json` (search: `modernisation.f-string-candidate`). Its M102 record-retirement transition preserves the historical review record under workspace ADR-010. Existing retired-id configuration, suppression and selection behavior above remains in force; no replacement is enabled. The other approved Python retirements remain pending.

## Remaining M02 retirements, 2026-10-17

The operator approved these twenty-eight additional retirements through M02's tables and M95's source scope, inherited by M102. Together with the f-string pilot they implement the twenty-nine approved Python deletions. The py-004 exception preserves `docs.missing-return-doc` for a bounded repair.

- complexity: `complexity.halstead-volume`, `complexity.maintainability-index`.
- docs: `docs.useless-docstring`.
- naming: `naming.boolean-prefix`, `naming.confusing-name`, `naming.hungarian-notation`, `naming.module-name-mismatch`.
- security: `security.unsanitized-markdown-interpolation`.
- sensitive-data: `sensitive-data.pii-test-fixture`.
- test-quality: `test-quality.conditional-logic`, `test-quality.eager-test`, `test-quality.exception-type-only`, `test-quality.extends-production-class`, `test-quality.loop-in-test`, `test-quality.magic-number-assertion`, `test-quality.mock-without-expectation`, `test-quality.multiple-aaa-cycles`, `test-quality.mystery-guest`, `test-quality.parametrize-annotation`, `test-quality.skipped-without-reason`, `test-quality.sleep-in-test`, `test-quality.tautological-type-assertion`, `test-quality.trivial-snapshot`.
- waste: `waste.commented-out-code`, `waste.empty-class`, `waste.one-line-function`, `waste.redundant-variable`, `waste.unused-import`.

The catalogue falls from 124 to 96; all ninety-six surviving native records compare exactly with the committed pilot. The native absence table preserves positive source cases and explicitly enables each old setting. Halstead and maintainability calculations remain available through `metric-calibration`, whose three-metric output and default threshold payloads compare byte-for-byte. Shared calculation tests and the retained documentation rule's content-word helper remain; retired-only Markdown helpers and options are removed.

The workspace records an M102 record-retirement transition preserving every prior native record and reviewed judgment under workspace ADR-010. Original retired-id configuration behaviour remains in force. Workspace `0.6.0-precision-floor/evidence/m02/py-retirements/` retains source and measurement evidence. Final verification, remaining default-off decisions and repairs, and milestone acceptance remain separate gates.

## M02 opt-in dispositions, 2026-10-17

The operator approved continuation of M02's accepted nine-row default-off table under the source scope inherited by M103. Six retained rules become opt-in:

- `security.dangerous-function-call`: ten right of fifteen judged, with ten unresolved labels; provenance review remained insufficient.
- `security.header-injection`: neither of two judged findings was right, with one unresolved label; provenance review remained insufficient.
- `security.unsafe-yaml-load`: two right of three judged, with one unresolved label; provenance review remained insufficient.
- `security.variable-import`: three right of eleven judged, with eight unresolved labels; provenance review remained insufficient.
- `security.xxe`: only three default findings, two right and one unresolved, leave insufficient evidence.
- `sensitive-data.database-url-password`: none of seven judged findings was right; eight default findings are too few for deletion.

`complexity.cyclomatic`, `test-quality.no-assertions` and `test-quality.sut-not-called` retain their existing opt-in defaults. Their measured reasons are recorded beside the six new dispositions in generated `docs/rules.md` (search: `Default-off reason`). All nine rules stay registered and emit on their existing positive source cases when configuration enables them. Include-rule filters do not enable a disabled rule. The detector predicates and other native metadata remain unchanged.

The workspace records the six enablement changes as an additive M103 catalogue transition, preserving the earlier chain, and marks their review records shadow, score-neutral, exit-ineligible and hook-ineligible. Measurements and reviewed judgments are unchanged; capture, recall accounting and final milestone acceptance remain separate verification gates.

## Reversibility

A retired rule can return as a new, measured rule; `.goat-flow/plans/0.7.0-roadmap/rules-to-rebuild.md` in the workspace
keeps its wrong shapes and what a rebuilt rule needs. A rule turned off comes back on by removing `default_enabled=False`
once a measurement establishes its applicable precision floor.
