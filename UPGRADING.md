# Upgrading

How to move a project between `gruff-py` release lines, what each minor bump breaks, and how to go back. Every breaking change below matches `CHANGELOG.md`.

## What is stable inside a release line

- Rule identifiers keep their meaning and are never renamed or repurposed within a `0.x` patch series.
- Configuration filenames, documented keys, and severity-gate exit codes stay stable across patch releases.
- Machine-output schema versions change only on a minor release (`0.5.x` → `0.6.0`).

## What changes in `0.6.0`

`0.6.0` is a coordinated family release: the same breaking changes land across all five gruff ports at once so polyglot repositories upgrade once instead of port by port.

1. **Machine JSON moves to `gruff.analysis.v3` and `gruff.summary.v3`.** There is no v2 compatibility writer. Update v2 consumers to read skipped and missing paths under `paths`, the composite from `score.composite.{score,grade}`, changed-region counts from `summary.suppressedFindings` and `diff.filteredFindings`, and Python-only run data from `run.extensions.py.run`. `summary --format json` is now the analysis document with only top-level `findings` removed.
2. **The agent-hook contract moves from `gruff.hook.v1` to `gruff.hook.v2`.** The payload adds two required top-level keys: `run` (mode, scope, operands, `analysedFiles`, applied baseline) and `suppressions` (one row per configured sensitive exclusion plus built-in, inline, and duplicate audit rows). Exit codes are ratified as `0` (clean or below gate), `1` (finding or diagnostic matched `--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` (run could not complete). Update consumers that validate the exact payload key set.
3. **`list-rules --format json` publishes thresholds as a `thresholds` map.** Single-threshold rules move from scalar `threshold` to a named map (such as `{"maxLines": 100}` or `{"threshold": 10}`); rules with no threshold omit the key. `list-rules <rule_id> --format json` changes the same way. `.gruff-py.yaml` keys and SARIF properties are unchanged.
4. **The per-command exit gate moves from `minimumSeverity:` to `failOn:`.** A `0.5` config carrying a per-command `minimumSeverity:` map exits `2` and names `failOn` (`analyse`, `report`, `dashboard` in YAML or `[tool.gruff-py.failOn]`). `minimumSeverity` survives only as a scalar display floor (`advisory`, `warning`, or `error`, not `none`) that sets `--min-severity` without affecting scores or exit codes. Run `gruff-py migrate-config --output gruff-py.migrated.yaml` (or `--dry-run` to preview) to rename the key without modifying the original file.
5. **Baselines move to `gruff.baseline.v3`, and finding identities change once.** Baseline rows now store a line-free SHA-256 identity (language, rule id, project-relative path, and symbol plus declaration ordinal — or digit-normalized message when no symbol exists) and a count, so edits above a finding no longer expire reviews. Old `v1` baselines fail closed; carry reviews forward with `gruff-py analyse --migrate-baseline gruff-baseline.json --generate-baseline=gruff-baseline.v3.json`, which leaves the original file untouched.
6. **Sensitive-data findings cannot be baselined and now default to `warning`.** Generated baselines count secrets under `sensitive.counts` with no row or path, and hand-written baseline rows cannot hide them; silence intentional fixtures with reason-bearing `sensitiveExclusions:` entries instead. All `sensitive-data.*` rules now default to `warning` (six previously defaulted to `error`), so `--fail-on error` no longer fails on them unless you set `severity: error` per rule.
7. **SARIF `partialFingerprints.gruffFingerprint` uses the durable identity, and secrets emit none.** Existing code-scanning alerts close and reopen once on upgrade, then survive ordinary edits. Sensitive-data findings publish no `partialFingerprints` so secrets are never given durable names in external tooling.
8. **Scores move to the normalized family curve with a fixed 12-pillar divisor.** Pillar scores use `floor + (100 - floor) / (1 + density / densityScale)` over `score.evaluatedFiles` (duplicating a project no longer lowers its grade), the composite averages all 12 pillars so fixing a finding never reduces the score, `score.pillars[].penalty` publishes raw weight (no 4x/5x multiplier), ties round half away from zero, and empty or unparsed runs publish `null` grades (`Composite: n/a (nothing evaluated)`). Six rules also update confidence from measured precision (`complexity.cognitive`, `docs.dataclass-attributes`, `docs.missing-module-docstring`, `naming.identifier-quality`, `naming.short-variable`, `waste.empty-function`). Recalibrate any score thresholds tuned against `0.5.x`.
9. **Empty or unreadable `--changed-ranges` exits `2` instead of scanning everything.** `--changed-ranges=` now exits `2` with one `changed-region` diagnostic and no findings on both `analyse` and `hook`. Callers that compute a range that can legitimately be empty should skip the run instead of passing an empty flag.
10. **Default file discovery follows the family fallback policy, and security/sensitive-data rules skip test paths.** Non-VCS scans defer to `.gitignore`, explicit supported files bypass Git and fallback exclusions, and `vendor`/`vendors`/`third_party`/`third-party`/`bower_components`/`dist` directories plus `*.min.*` files are skipped by default. Every shipping security and sensitive-data rule also skips test, fixture, and example paths (`test`, `tests`, `__tests__`, `spec`, `testdata`, `fixtures`, `examples`, `test_*.py`, `*_test.py`, etc.) and counts each skip as a `source: "built-in"` audit row. Real credentials or unsafe calls committed under those paths are no longer reported.
11. **Nine size and complexity rules report in two bands.** Values over the limit and under `1.5x` report as `advisory` (`limitBand: lower`); values at `1.5x` or above keep their configured severity (`limitBand: upper`). Both bands phrase breaches as `"above the limit of <N>"` so crossing bands keeps the same identity. `--fail-on warning` and `--fail-on error` stop failing on lower-band findings; default `analyse` still fails on `advisory`. Length rules also count code lines only (blank lines, comments, docstrings, and decorators are free).
12. **Documentation defaults widen to private callables, and `docs.missing-param-doc` reports once per function.** `docs.missing-function-docstring`, `docs.missing-param-doc`, and `docs.missing-raises-doc` default `everyCallable: true`. Under `docs.missing-function-docstring`, `test_*` functions in recognized test files report at `advisory` severity while production and helper callables stay at `warning`. `docs.missing-param-doc` lists every missing parameter in one finding under `metadata.parameters` (replacing `metadata.parameter`). Set `rules.<id>.options.everyCallable: false` to limit a rule to public callables.
13. **36 rules are removed (ADR-029).** Delete these IDs from inline `# gruff: disable=` comments, `selection`, `sensitiveExclusions`, and the `--include-rule`, `--exclude-rule`, `--show-rule`, and `--hide-rule` flags, all of which now exit `2`. Obsolete `rules:` blocks warn by default (or fail under `--strict-config`).
    - `complexity`: `complexity.halstead-volume`, `complexity.maintainability-index`.
    - `dead-code`: `dead-code.unused-private-function`.
    - `docs`: `docs.complex-branch-rationale`, `docs.useless-docstring`.
    - `modernisation`: `modernisation.f-string-candidate`.
    - `naming`: `naming.boolean-prefix`, `naming.confusing-name`, `naming.hungarian-notation`, `naming.module-name-mismatch`.
    - `security`: `security.django-mark-safe`, `security.sql-concatenation`, `security.unsanitized-markdown-interpolation`.
    - `sensitive-data`: `sensitive-data.high-entropy-string`, `sensitive-data.pii-test-fixture`.
    - `test-quality`: `test-quality.conditional-logic`, `test-quality.eager-test`, `test-quality.exception-type-only`, `test-quality.extends-production-class`, `test-quality.loop-in-test`, `test-quality.magic-number-assertion`, `test-quality.mock-without-expectation`, `test-quality.multiple-aaa-cycles`, `test-quality.mystery-guest`, `test-quality.parametrize-annotation`, `test-quality.private-reflection`, `test-quality.skipped-without-reason`, `test-quality.sleep-in-test`, `test-quality.tautological-type-assertion`, `test-quality.trivial-snapshot`.
    - `waste`: `waste.commented-out-code`, `waste.empty-class`, `waste.one-line-function`, `waste.redundant-variable`, `waste.unused-import`, `waste.unused-parameter`.
14. **27 rules are now opt-in.** Enable any retained rule explicitly with `rules.<id>.enabled: true` (`--include-rule` alone does not turn an opt-in rule on; existing explicit `enabled: true` settings stay active). See [docs/rules.md](docs/rules.md) for per-rule reasons.
    - `complexity`: `complexity.cyclomatic`.
    - `dead-code`: `dead-code.exported-but-unreferenced`.
    - `docs`: `docs.missing-return-doc`.
    - `naming`: `naming.generic-function`.
    - `security`: `security.dangerous-function-call`, `security.django-raw-sql`, `security.github-actions-secrets-in-pr`, `security.hardcoded-framework-secret-key`, `security.header-injection`, `security.insecure-temp-file`, `security.shell-injection`, `security.silent-except`, `security.unsafe-pickle`, `security.unsafe-yaml-load`, `security.variable-import`, `security.weak-crypto`, `security.xxe`.
    - `sensitive-data`: `sensitive-data.api-key-pattern`, `sensitive-data.database-url-password`, `sensitive-data.private-key`, `sensitive-data.url-credentials`.
    - `test-quality`: `test-quality.loop-assertion-without-message`, `test-quality.no-assertions`, `test-quality.setup-bloat`, `test-quality.sut-not-called`, `test-quality.test-function-too-long`, `test-quality.trivial-assertion`.

## Upgrade workflow (`0.5.x` → `0.6.0`)

1. Review the list above to see which breaks affect your repository. Projects without a committed baseline or custom config mainly see the rule, scoring, and docstring default changes.
2. Upgrade the package:

   ```bash
   uv add --dev 'gruff-py>=0.6,<0.7'
   ```

3. Migrate your configuration: run `gruff-py migrate-config --output gruff-py.migrated.yaml` (or `--dry-run` to preview) to rename `minimumSeverity:` to `failOn:`, or `gruff-py init --force` to rewrite a valid `.gruff-py.yaml` while preserving supported settings. Delete inline `# gruff: disable=` comments that name retired rules (such as `security.unsanitized-markdown-interpolation`), because `migrate-config` edits config files only and retired inline suppressions exit `2`.
4. Carry a baseline forward rather than regenerating it so reviewed findings stay reviewed:

   ```bash
   gruff-py analyse --migrate-baseline gruff-baseline.json --generate-baseline=gruff-baseline.v3.json
   ```

   Use `--generate-baseline=PATH` for an explicit destination. Migration leaves the original `0.5.x` baseline untouched so you can inspect the diff before replacing your default file.
5. Run `gruff-py summary . --group-by rule` and verify rule counts, scores, and any `sensitiveExclusions:` entries before re-enabling CI gates.

## Limitations

- Baselines generated before `0.6.0` cannot be loaded directly. Migrate them rather than hand-editing them.
- Sensitive-data findings are not baselineable in `0.6.0`. Replace baselined secrets with reason-bearing `sensitiveExclusions:` entries.
- Finding identities change once at this release. Previously reviewed findings appear as new until baseline migration runs.

## Retreat

If the upgrade costs more than it is worth today, pin the previous line and come back later:

```bash
uv add --dev 'gruff-py>=0.5,<0.6'
```

Keep your pre-upgrade config and baseline files. `0.5.x` still reads them, and `--migrate-baseline` remains available whenever you return.

## Reporting an upgrade regression

Open an issue at <https://github.com/blundergoat/gruff-py/issues> with the version you moved from, the version you moved to, the command you ran, and the finding that changed. A finding that moved without a documented break above is a regression rather than an upgrade cost.
