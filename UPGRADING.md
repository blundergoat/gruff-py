# Upgrading

How to move a project between `gruff-py` lines, what each move breaks, and how to go back.
Every break below is the one this port's own `CHANGELOG.md` records; nothing here is a plan.

## What is stable across `0.5.x`

- Rule identifiers. A released `ruleId` keeps its meaning; it is not renamed or repurposed inside a line.
- The configuration file's name and its documented keys.
- Exit codes for the documented severity gate.
- The analysis envelope's schema version, which changes only on a minor line.

## What changes in `0.6.0`

`0.6.0` is a coordinated family release: the same break lands in all five ports rather than one at a
time, so a project using more than one of them moves once. This port's recorded breaks are:

1. **baselines move to the family `gruff.baseline.v3` file, and every finding identity changes once** — A baseline row now stores one line-free identity and a count: sha256 over the tool language, native rule id, project-relative path, and a subject that is the symbol plus its declaration ordinal, or, when no symbol is named, the message with its measured values normalised. The rest of this entry is in `CHANGELOG.md`.
2. **sensitive-data findings can no longer be baselined** — A generated baseline counts them by rule under `sensitive.counts` and stores no row, path, or message for them, and a hand-written row cannot hide one: a secret stays visible and blocking until it is fixed or excluded with a reason under `sensitiveExclusions`.
3. **SARIF `partialFingerprints.gruffFingerprint` is the ratified identity, and a secret carries none** — Code scanning grouped alerts by the line-bearing fingerprint, so an alert closed and reopened every time code moved above it. It is now the same durable identity baseline matching reads: every existing alert closes and reopens once at this break, and each one then survives an ordinary edit. Two same-named declarations in one file, previously one alert, become two. The rest of this entry is in `CHANGELOG.md`.
4. **every score changes - the family adopts one normalized scoring formula** — A pillar is now `floor + (100 - floor) / (1 + density / densityScale)`, where `density` is the pillar's summed severity-by-confidence weight divided by the number of Python files that were actually evaluated. Scores no longer track project size: duplicating a project leaves its grade unchanged, where before it fell. The rest of this entry is in `CHANGELOG.md`.
5. **the composite can be null, and so can a pillar or file grade** — `score.composite.{score,grade}` are `null` when the run evaluated nothing at all: an empty directory, or one whose every Python file failed to parse, previously reported a perfect `100` and grade `A`. Every human view renders `Composite: n/a (nothing evaluated)` in that case.
6. **`score.pillars[].penalty` is the raw weight** — It was the summed weight multiplied by 4 for a pillar and 5 for a file; both multipliers belonged to the retired absolute-sum formula and are gone. A pillar with one high-confidence error now publishes `penalty: 12`, not `48`.
7. **machine JSON uses `gruff.analysis.v3` and `gruff.summary.v3`** — Replace v2 consumers: read ignored and missing paths under `paths`, the composite from `score.composite.{score,grade}`, changed-region counts from `summary.suppressedFindings` and `diff.filteredFindings`, and Python-only run data from `run.extensions.py.run`; `summary --format json` is the analysis document with only top-level `findings` removed. The rest of this entry is in `CHANGELOG.md`.
8. **default scans use the family fallback policy** — Non-VCS fallbacks now defer to any governing `.gitignore`, committed control metadata stays scannable, and explicit supported files bypass Git and fallback exclusions. Python retains its named cache and environment exceptions; eligible lockfiles are no longer dropped by filename, while VCS internals remain blocked.
9. **composite scores move because the divisor no longer changes between runs** — The composite averaged only the pillars a run happened to produce findings for plus a fixed ten, so `correctness` and `modernisation` joined the average only when they had findings and dropped out when the last one was fixed. Fixing a finding could therefore *lower* the score: a measured run fell from 80.18 (B) to 79.00 (C) when two `modernisation` findings were resolved. The rest of this entry is in `CHANGELOG.md`.

10. **the per-command exit gate moves from `minimumSeverity:` to `failOn:`** — A `0.5` config carrying the per-command `minimumSeverity:` map is refused at load time with exit `2`, and the message names `failOn` as the key that gates the exit code. `failOn` accepts `analyse`, `report` and `dashboard`, in both `.gruff-py.yaml` and `[tool.gruff-py.failOn]`. `minimumSeverity` still loads, but only as a scalar display floor that sets the `--min-severity` default and never changes the exit code or the score, and it takes `advisory`, `warning` or `error` rather than `none`. This is the ratified family contract (`gruff-spec/contracts/core/cli.v1.json`, ratified 2026-09-06: "minimumSeverity is display, failOn is the gate"). Recover with `gruff-py migrate-config`, which renames the key and leaves the original file untouched.

## Upgrade workflow (`0.5.x` → `0.6.0`)

1. Read the list above and decide which breaks touch your project. A project with no committed
   baseline and no hand-written configuration is usually unaffected by all but the rule changes.
2. Upgrade the package:

   ```bash
   uv add --dev 'gruff-py>=0.6,<0.7'
   ```

3. Regenerate the configuration if you hand-wrote one: `gruff-py init --force` rewrites it
   with the current schema version and preserves the tuning you already had.
4. Carry a baseline forward rather than regenerating it, so previously reviewed findings stay
   reviewed:

   ```bash
   gruff-py analyse --migrate-baseline gruff-baseline.json --generate-baseline gruff-baseline.v3.json
   ```

   This is the migration the tool demands when it refuses a `0.5` baseline; its own message spells
   the output flag `--generate-baseline-path`, which behaves identically. It writes a separate
   file and preserves the original, so swap the two names once you have compared them. The full
   rationale is in the `CHANGELOG.md` entry for the baseline break.
5. Re-run `gruff-py summary .` and compare the finding count with the one you had. A rule
   whose default changed will move it; a rule whose identity changed will not.

## Limitations

- A baseline generated before `0.6.0` cannot be read directly. Migrate it; do not hand-edit it.
- Sensitive-data findings are not baselineable in `0.6.0`. A project that had suppressed them through
  a baseline needs a reason-bearing configuration exclusion instead.
- Identities change once, at this release. A finding you had already reviewed will look new until the
  migration has run.

## Retreat

If the upgrade costs more than it is worth today, pin the previous line and come back to it:

```bash
uv add --dev 'gruff-py>=0.5,<0.6'
```

Keep the pre-upgrade baseline file. It stays readable by the line that produced it, and the migration
command reads it whenever you return.

## Reporting an upgrade regression

Open an issue at <https://github.com/blundergoat/gruff-py/issues> with the version you moved
from, the version you moved to, the command you ran, and the finding that changed. A finding that
moved without a break above it is a regression rather than an upgrade cost.
