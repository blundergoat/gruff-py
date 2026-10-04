# ADR-029: Rules wrong more often than right are retired, not tuned

**Status:** Accepted
**Date:** 2026-10-05
**Author(s):** Claude, user direction
**Ticket/Context:** precision-floor M19 under family lock M82. The operator ruled on 2026-10-04 that a rule right less than
half the time is deleted, and accepted the gruff-py table with "Accept all (Recommended)". The same decision is gruff-go
ADR-021 and gruff-php ADR-034.

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

## Reversibility

A retired rule can return as a new, measured rule; `.goat-flow/plans/0.7.0-roadmap/rules-to-rebuild.md` in the workspace
keeps its wrong shapes and what a rebuilt rule needs. A rule turned off comes back on by removing `default_enabled=False`
once a measurement on more findings puts it at half or better.
