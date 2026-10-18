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

11. **the agent-hook contract moves from `gruff.hook.v1` to `gruff.hook.v2`** — The payload's `contractVersion` changes and the envelope gains two required keys, `run` and `suppressions`. `run` carries the audit data a consumer needs to trust the verdict — mode, scope, the operands as given, `analysedFiles`, and the applied baseline — and `suppressions` carries one row per configured sensitive exclusion with the count it suppressed in this run, `0` when the entry matched nothing, and `[]` when none are configured. The exits are ratified as three and no others: `0` when nothing reached the gate, `1` when something did under an explicit consumer request (`--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` when the run could not happen. Update any consumer that validates the payload's key set; one that reads only the keys it needs is unaffected. The contract is `gruff-spec/contracts/core/hook.v2.json`, ratified 2026-09-06.

12. **`list-rules --format json` publishes every threshold as a named knob map** — A single-threshold rule's value moves from the scalar `threshold` to `thresholds`, as `{"maxLines": 100}` where gruff-go already names the knob and `{"threshold": 10}` where no port does; named-knob rules keep their map, and a rule with no threshold publishes neither key. Update any consumer that read `rules[].threshold`; `list-rules <rule_id> --format json` changes the same way. SARIF rule properties and `.gruff-py.yaml` keys are unchanged.

13. **five rules are removed** — `dead-code.unused-private-function` (right on 3 of 25 judged findings), `security.django-mark-safe` (7 of 37), `security.sql-concatenation` (4 of 37), `sensitive-data.high-entropy-string` (1 of 25) and `waste.unused-parameter` (4 of 25) were each right less than half the time in the 0.6.0 precision measurement. A `# gruff: disable=` comment that names one now invalidates the run with a `suppression-unknown-rule` diagnostic and exit `2`, so delete those comments first. A `selection` list or `sensitiveExclusions` entry that names one exits `2`; a `rules:` block that names one is ignored with a warning; a baseline row for one is kept and matches nothing. `--include-rule` and `--exclude-rule` accept a retired id silently, so a run narrowed to one with `--include-rule` now runs no rule and passes; check CI commands for them. The decision is ADR-029.

14. **an empty `--changed-ranges` is refused instead of scanning everything** — `--changed-ranges=` asks for a scoped run and names no range, and it was read as "no filter": the run silently widened to the whole tree and exited `0`. It now exits `2` with one `changed-region` diagnostic and no findings, on analyse and on the hook. A caller that passes a computed range which can legitimately come back empty must skip the run rather than pass the empty value; the shipped `gruff-code-quality.sh` wrapper already does.

15. **sensitive-data rules skip test, fixture and example files** — Every shipping sensitive-data rule skips a file under a `test`, `tests`, `__tests__`, `spec`, `testdata`, `fixtures` or `examples` directory, or named like a test file, and publishes each skip as a counted `source: "built-in"` audit row. A real credential committed under one of those paths is no longer reported. The rest of this entry is in `CHANGELOG.md`.

16. **five rules are off by default** — `security.django-raw-sql`, `security.github-actions-secrets-in-pr`, `security.shell-injection`, `sensitive-data.api-key-pattern` and `sensitive-data.url-credentials` each scored below half on fewer than ten findings. Enable one with `rules.<id>.enabled: true`; `--include-rule` narrows the run to rules already on and does not turn one on. A config written by an earlier `init` lists them as `enabled: true` and keeps them on. The decision is ADR-029.

17. **length rules count code lines only** — Function, class, average-function and test-function length, setup length, the test-to-subject ratio and the maintainability index's line term now count code lines only: docstrings, comments, blank lines and decorators are free, as file length already treated docstrings and comments. File length now leaves decorator lines out as well. A documented unit can stop reporting, and a finding's `metadata.lines` falls when the unit carries documentation; no threshold changes and no finding moves. This is the family contract's code-lines clause, ratified 2026-10-09.

18. **`docs.useless-docstring` no longer counts words, and `min_summary_words` is ignored** — The rule now reports only a public function's summary that restates its name and parameters. A short accurate summary on a function, class or module is accepted whatever its word count. `rules.docs.useless-docstring.options.min_summary_words` still loads without error but has no effect; remove it, because `0.7.0` drops it.

19. **`docs.missing-param-doc` reports a function once, and four documentation rules can widen** — The rule names every undocumented parameter in one finding and lists them in `metadata.parameters`; the per-finding `metadata.parameter` key is gone, so a consumer reading it must read the list. On the 0.6.0 precision measurement's twelve Python repositories that removed 121 findings at the defaults. `docs.missing-function-docstring` messages now say what the docstring needs. The `everyCallable` option is off by default; turning it on for all four documentation rules there added 25,791 `docs.missing-function-docstring`, 4,536 `docs.missing-return-doc`, 1,432 `docs.missing-param-doc` and 244 `docs.missing-raises-doc` findings, taking the total from 89,593 to 121,596. The rest of this entry is in `CHANGELOG.md`.

20. **`modernisation.f-string-candidate` is removed** — The accepted precision table found no right labels among 23 judged findings. Remove its selection entries and suppression comments, which now exit `2`; obsolete `rules:` settings are ignored with a warning. CLI include/exclude filters still accept the retired id, and a run narrowed to it runs no rule. No replacement is enabled.

21. **Twenty-eight further rules are removed** - Remove the IDs listed in [CHANGELOG.md](CHANGELOG.md) from selections, sensitive exclusions and suppression comments. Obsolete `rules:` blocks warn, or fail with `--strict-config`; include/exclude filters accept retired IDs but cannot make them run. Earlier tuning and opt-in instructions for those IDs are superseded. `metric-calibration` retains all three metrics at its existing defaults; retired complexity settings no longer configure findings.

22. **six more rules become opt-in** - `security.dangerous-function-call`, `security.header-injection`, `security.unsafe-yaml-load`, `security.variable-import`, `security.xxe` and `sensitive-data.database-url-password` remain available but stop reporting at the defaults. M02's accepted measurements did not establish their precision floors; each reason is recorded in [docs/rules.md](docs/rules.md). Enable one with `rules.<id>.enabled: true`; `--include-rule` only filters enabled rules. Existing explicit `enabled: true` settings keep a rule running. Cyclomatic complexity, no-assertions and sut-not-called retain their existing opt-in defaults.

23. **return documentation remains available as an opt-in check** - `docs.missing-return-doc` is retained under the return-documentation exception, with a bounded repair that recognizes result prose instead of requiring a Returns section. It is off by default until fresh blind validation establishes its precision floor. Set `rules.docs.missing-return-doc.enabled: true` to use it; an existing explicit enable setting stays effective. Findings ask you to describe the result in prose or a return field.

24. **silent-except becomes opt-in** - `security.silent-except` recognizes explanatory comments inside a handler, but M02's complete repaired census remains below the 0.80 security floor at 21 right of 29 judged findings. The enabled repair preserves all 22 occurrences judged right across both versions; default scans omit them. Set `rules.security.silent-except.enabled: true` to retain this check. Existing explicit enable settings remain effective; `--include-rule` alone does not enable it.

25. **Framework SECRET_KEY check becomes opt-in** - `security.hardcoded-framework-secret-key` stays registered with the same detection logic, but one remaining corpus finding is too little evidence to establish the security precision floor. Default scans omit this check. Set `rules.security.hardcoded-framework-secret-key.enabled: true` to retain it; existing explicit enable settings remain effective, and `--include-rule` alone does not enable it.

26. **Insecure temporary-file check becomes opt-in** - `security.insecure-temp-file` retains its detector, but no current corpus findings survive the shared test-path exclusion, so its security precision floor remains unmeasured. Set `rules.security.insecure-temp-file.enabled: true` to use it; existing explicit enable settings remain effective, and `--include-rule` alone does not enable it. Test, fixture and example paths remain excluded when enabled.

27. **Weak-crypto becomes opt-in** - `security.weak-crypto` stays registered but no longer runs by default because its enabled corpus has fewer than ten findings, too few to assess the security precision floor. Set `rules.security.weak-crypto.enabled: true` to use the bounded repair; existing explicit enable settings remain effective, and `--include-rule` alone does not enable it. A no-argument MD5 or SHA1 constructor used only for `digest_size` stays quiet, while incremental password hashing still reports when enabled.

28. **Private-key detection becomes opt-in** - Enable `rules.sensitive-data.private-key.enabled: true` to retain this check. The bounded repair excludes adjacent marker-only parser constants, but its small enabled corpus cannot establish the 0.80 sensitive-data precision floor. Existing explicit enable settings remain effective; `--include-rule` alone does not enable it. Enabled scans retain warnings for opaque, incomplete and unmatched key material, with redacted previews.

## Upgrade workflow (`0.5.x` → `0.6.0`)

`naming.generic-function` becomes opt-in because its bounded repair remains below the 0.60 naming floor at 28 right of 49 judged findings. Set `rules.naming.generic-function.enabled: true` to retain it; `--include-rule` alone does not enable it. Enabled scans accept required methods on explicitly imported Django commands (`handle`, `execute`), docutils directives (`run`), threads (`run`) and logging handlers (`handle`). Import aliases are supported; ambiguous bindings and unrecognized bases still report. Options and remediation are unchanged.

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
