# Changelog

All notable changes to `gruff-py`. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org) with the pre-1.0 caveat: while the project is on `0.MINOR.PATCH`, a minor bump (`0.1.x → 0.2.0`) is permitted to break. Every breaking change carries a `BREAKING:` marker and a migration path regardless of which component moves; the only thing pre-1.0 relaxes is the version-number signal.

## v0.6.0 - 2026-11-27

`0.6.0` is a coordinated family release aligning every machine-readable contract across all five gruff ports and trimming the catalogue from 130 rules across 12 pillars to 94 rules across 10 pillars (67 default-enabled, 27 opt-in, 36 removed). See `UPGRADING.md` for step-by-step migration commands and the retreat path to `0.5.x`.

### Breaking changes

- **BREAKING: machine JSON moves to `gruff.analysis.v3` and `gruff.summary.v3`** - Update v2 consumers: ignored and missing paths move under `paths`, the composite moves to `score.composite.{score,grade}`, changed-region counts move to `summary.suppressedFindings` and `diff.filteredFindings`, and Python-only run metadata moves under `run.extensions.py.run`. `summary --format json` is the analysis document with only top-level `findings` removed. There is no v2 compatibility writer.
- **BREAKING: agent-hook output moves from `gruff.hook.v1` to `gruff.hook.v2`** - The envelope adds required `run` (mode, scope, operands, `analysedFiles`, applied baseline) and `suppressions` keys, and ratifies exit codes as `0` (ran cleanly below gate), `1` (met explicit `--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` (run could not complete). Consumers validating the exact key set must accept the two new keys.
- **BREAKING: `list-rules --format json` publishes thresholds under `thresholds`** - Single-threshold rules move from scalar `threshold` to a named `thresholds` map (such as `{"maxLines": 100}` or `{"threshold": 10}`); rules with no threshold omit the key. `list-rules <rule_id> --format json` changes the same way; `.gruff-py.yaml` and SARIF rule properties are unchanged.
- **BREAKING: the per-command exit gate moves from `minimumSeverity:` to `failOn:`** - A per-command `minimumSeverity:` map now exits `2` and points to `failOn` (`analyse`, `report`, `dashboard` in YAML or `[tool.gruff-py.failOn]`). `minimumSeverity` survives only as a scalar display floor (`advisory`, `warning`, or `error`, not `none`) that sets `--min-severity` without changing scores or exit codes and is recorded under `displayFilter`. Run `gruff-py migrate-config --output gruff-py.migrated.yaml` (or `--dry-run` to preview) to rename the key without modifying the original file.
- **BREAKING: baselines move to `gruff.baseline.v3`, and finding identities change once** - Each row stores a line-free SHA-256 identity (language, rule id, project-relative path, and symbol plus file-wide declaration ordinal — or digit-normalized message when no symbol exists) and a count, so edits above a finding no longer expire reviews and same-named functions never inherit each other's review. Old `v1` baselines fail closed; migrate them with `gruff-py analyse --migrate-baseline <old> --generate-baseline=<new>` (the original file stays untouched). Generating at default `gruff-baseline.json` refuses to overwrite a non-v3 file unless `--force` is passed. Collisions stay visible with a `baseline-collision` diagnostic, and the analysis `baseline` container always emits its full key set.
- **BREAKING: sensitive-data findings cannot be baselined and now default to `warning`** - Generated baselines count secrets by rule under `sensitive.counts` with no per-finding row, and hand-written rows cannot hide them; silence reviewed matches with reason-bearing `sensitiveExclusions:` entries instead. All `sensitive-data.*` rules now default to `warning` (six previously defaulted to `error`: `aws-access-key`, `database-url-password`, `gcp-service-account-key`, `phi-pattern`, `private-key`, `url-credentials`), so `--fail-on error` no longer fails on them unless you set `severity: error` per rule.
- **BREAKING: SARIF `partialFingerprints.gruffFingerprint` uses the durable identity, and secrets emit none** - Existing code-scanning alerts close and reopen once on upgrade, then survive line shifts. Sensitive-data findings omit `partialFingerprints` so secrets are never given durable names in external systems.
- **BREAKING: scoring moves to the normalized family curve with a fixed 12-pillar divisor** - Pillar scores use `floor + (100 - floor) / (1 + density / densityScale)` over `score.evaluatedFiles` (duplicating a project no longer changes its grade), the composite averages all 12 pillars on every run so fixing a finding never lowers the score, `score.pillars[].penalty` publishes raw weight (removing the 4x/5x multipliers), `score.topOffenders[]` uses the same curve with raw `penalty`, ties round half away from zero, and empty or wholly unparsed runs publish `null` composite and grades (`Composite: n/a (nothing evaluated)`). `score.evaluatedFiles` and `score.scoredPillars` are now published. Six rules also update confidence from measured precision: `complexity.cognitive` (high to medium), `docs.dataclass-attributes` (medium to high), `docs.missing-module-docstring` (medium to high), `naming.identifier-quality` (high to low), `naming.short-variable` (low to high), and `waste.empty-function` (high to medium).
- **BREAKING: empty or unreadable `--changed-ranges` exits `2` instead of widening** - Passing `--changed-ranges=` or an unreadable range now exits `2` with one `changed-region` diagnostic and no findings on both `analyse` and `hook`, rather than falling back to a whole-tree scan.
- **BREAKING: default file discovery follows the family fallback policy** - Non-VCS scans defer to `.gitignore`, explicit supported file operands bypass Git and fallback exclusions, eligible lockfiles are no longer skipped by filename, and VCS internals remain blocked. Directories named `vendor`, `vendors`, `third_party`, `third-party`, `bower_components`, or `dist` (any case or depth) and `*.min.*` files are skipped by default even under `.gitignore`; `--include-ignored` or an explicit file operand scans them.
- **BREAKING: nine size and complexity rules report in two bands** - Values above the limit and under `1.5x` report as `advisory` (`limitBand: lower`); values at `1.5x` or above keep their configured severity (`limitBand: upper`). This covers `size.file-length`, `size.class-length`, `size.function-length`, `size.parameter-count`, `size.attribute-count`, `size.public-method-count`, `complexity.cognitive`, `complexity.cyclomatic`, and `complexity.nesting-depth`. Both bands use the same `"above the limit of <N>"` wording so crossing bands preserves identity, and complexity advice no longer suggests extracting helpers. `--fail-on warning` and `--fail-on error` stop failing on lower-band findings; default `analyse` still gates on `advisory`.
- **BREAKING: documentation defaults widen to private callables, and `docs.missing-param-doc` reports once per function** - `docs.missing-function-docstring`, `docs.missing-param-doc`, and `docs.missing-raises-doc` default `everyCallable: true`. Under `docs.missing-function-docstring`, `test_*` functions in recognized test files report at `advisory` severity while production and helper callables stay at `warning`. `docs.missing-param-doc` emits one finding per function listing every missing parameter under `metadata.parameters` (replacing `metadata.parameter`) and rejects blank parameter descriptions. Set `rules.<id>.options.everyCallable: false` to limit a rule to public callables.
- **BREAKING: 36 rules are removed** - Precision measurements on unseen code left these rules below the 50% retention line (ADR-029). Remove their IDs from inline `# gruff: disable=` comments, `selection`, `sensitiveExclusions`, and the `--include-rule`, `--exclude-rule`, `--show-rule`, and `--hide-rule` flags, which now exit `2`; obsolete `rules:` blocks warn (or fail with `--strict-config`). `metric-calibration` retains its three metrics.
  - `complexity`: `complexity.halstead-volume`, `complexity.maintainability-index`.
  - `dead-code`: `dead-code.unused-private-function`.
  - `docs`: `docs.complex-branch-rationale`, `docs.useless-docstring`.
  - `modernisation`: `modernisation.f-string-candidate`.
  - `naming`: `naming.boolean-prefix`, `naming.confusing-name`, `naming.hungarian-notation`, `naming.module-name-mismatch`.
  - `security`: `security.django-mark-safe`, `security.sql-concatenation`, `security.unsanitized-markdown-interpolation`.
  - `sensitive-data`: `sensitive-data.high-entropy-string`, `sensitive-data.pii-test-fixture`.
  - `test-quality`: `test-quality.conditional-logic`, `test-quality.eager-test`, `test-quality.exception-type-only`, `test-quality.extends-production-class`, `test-quality.loop-in-test`, `test-quality.magic-number-assertion`, `test-quality.mock-without-expectation`, `test-quality.multiple-aaa-cycles`, `test-quality.mystery-guest`, `test-quality.parametrize-annotation`, `test-quality.private-reflection`, `test-quality.skipped-without-reason`, `test-quality.sleep-in-test`, `test-quality.tautological-type-assertion`, `test-quality.trivial-snapshot`.
  - `waste`: `waste.commented-out-code`, `waste.empty-class`, `waste.one-line-function`, `waste.redundant-variable`, `waste.unused-import`, `waste.unused-parameter`.
- **BREAKING: 27 rules are now opt-in** - Rules whose precision floor was not established or fell below its pillar floor stay registered but off by default; `docs/rules.md` lists each rule's reason. Enable any of them with `rules.<id>.enabled: true` (`--include-rule` alone does not turn an opt-in rule on; existing explicit `enabled: true` configs keep working).
  - `complexity`: `complexity.cyclomatic`.
  - `dead-code`: `dead-code.exported-but-unreferenced`.
  - `docs`: `docs.missing-return-doc` (also defaults `everyCallable: false` and recognizes result prose when enabled).
  - `naming`: `naming.generic-function` (accepts recognized Django command, docutils directive, thread, and logging handler hooks when enabled).
  - `security`: `security.dangerous-function-call`, `security.django-raw-sql`, `security.github-actions-secrets-in-pr`, `security.hardcoded-framework-secret-key`, `security.header-injection`, `security.insecure-temp-file`, `security.shell-injection`, `security.silent-except`, `security.unsafe-pickle`, `security.unsafe-yaml-load`, `security.variable-import`, `security.weak-crypto`, `security.xxe`.
  - `sensitive-data`: `sensitive-data.api-key-pattern`, `sensitive-data.database-url-password`, `sensitive-data.private-key`, `sensitive-data.url-credentials`.
  - `test-quality`: `test-quality.loop-assertion-without-message`, `test-quality.no-assertions`, `test-quality.setup-bloat`, `test-quality.sut-not-called`, `test-quality.test-function-too-long`, `test-quality.trivial-assertion`.

### Changed

- **Grouped summary rows show mixed severities** - `gruff-py summary --group-by rule` renders compact aligned per-severity counts (such as `7 error, 11 advisory`) when one rule emits multiple severities, while single-severity rows and `gruff.summary.v3` JSON stay unchanged.
- **New `sensitiveExclusions:` config section and `suppressions` audit rows** - Hand-written `sensitiveExclusions` entries silence reviewed sensitive-data matches by exact rule, project-relative path, optional symbol, and required reason, never by secret value. Both `analyse` and `summary` publish per-entry audit rows under `suppressions` (and under `Sensitive exclusions` in text output).
- **Security and sensitive-data rules skip test, fixture, and example files** - Both pillars skip files under `test`, `tests`, `__tests__`, `spec`, `testdata`, `fixtures`, or `examples` folders and conventional test filenames (`test_*.py`, `*_test.py`, etc.). Every skip is published as a counted `source: "built-in"` audit row rather than silenced invisibly.
- **Other tools' suppression comments are honoured, and duplicate dynamic imports merge** - Bare bandit `# nosec` comments suppress security and sensitive-data findings, and zizmor `ignore[unpinned-uses]` / `ignore[dangerous-triggers]` suppress the matching workflow rule (same line or line above; `# nosec B301` suppresses nothing). Dynamic `__import__` calls matched by both `security.dangerous-function-call` and `security.variable-import` report once under `security.dangerous-function-call`. Both appear in `suppressions` (`source: "inline"` / `"duplicate"`) and as suppressed SARIF results.
- **Bounded deep scans protect large files without dropping safety checks** - Python files over 20,000 lines or 2,000,000 bytes keep size, sensitive-data, and config checks while skipping AST analysis and emitting a non-fatal `bounded-deep-scan` diagnostic. Tune via `deepScanBudget` or `--deep-scan-budget LINES:BYTES|off`.
- **Typing generics and nested test helpers stop triggering false alarms** - `naming.short-variable` exempts `TypeVar`, `ParamSpec`, and `TypeVarTuple` bindings; `waste.empty-function` exempts classes nested inside test classes (`Test*`, `*Test`, `*TestCase`, `TestCase` subclasses) or test functions, plus pluggy hookspecs and direct `TYPE_CHECKING` ellipsis stubs; `docs.missing-class-docstring` exempts inline classes nested inside test functions or methods; and naming checks recognize singular `test/` folders.
- **Length rules count code lines only, and function length counts statements** - Blank lines, comments, PEP 257 docstrings, and decorators no longer count toward `size.file-length`, `size.function-length`, `size.class-length`, `size.average-function-length`, `test-quality.setup-bloat`, `test-quality.test-function-too-long`, or `test-quality.test-longer-than-sut`. Multi-line literals, wrapped calls, and wrapped signatures count as one statement in `size.function-length`, and `size.public-method-count` counts properties and `@overload` stubs once.
- **Copied tests group into one finding by default** - `test-quality.repeated-structure-missing-parametrize` defaults `groupFindings: true`, reporting three or more copied tests in one lexical container as a single finding listing every member; set `groupFindings: false` for per-test rows.
- **Lower false-positive rates across complexity, security, sensitive-data, docs, design, and test-quality rules** - `complexity.nesting-depth` treats `elif` chains as one level; `complexity.cyclomatic` skips test files and counts `match` as one decision; 20 vendor-documented sample credentials (matched by SHA-256), masked `AKIA`/`ASIA` AWS keys, stock local dev DB credentials (`sensitive-data.database-url-password`), template URL userinfo (`sensitive-data.url-credentials`), empty-line/placeholder `.env.example` entries (`sensitive-data.hardcoded-env-value`), and marker-only PEM parser constants (`sensitive-data.private-key`) stay quiet; `security.github-actions-secrets-in-pr` targets `pull_request_target` and skips unreachable event-guarded jobs/steps; `security.silent-except` accepts explanatory comments; `security.weak-crypto` skips no-arg `digest_size` constructors; `docs.missing-function-docstring` messages list only the missing sections; `docs.ignore-directive-reason` skips generated files and accepts issue references; `design.runtime-sys-path-mutation` allows top-level mutation in standalone scripts; `dead-code.exported-but-unreferenced` counts references from ignored paths; and test-quality rules accept named `subTest` loops, `pytest.param` ids, raising fakes, class-local assertion helpers, collected test files, plain `setup` outside test paths, and single literal response snapshots.
- **Safer remediation advice and clearer rule documentation** - Updated fix guidance for `security.insecure-temp-file`, `security.insecure-tls-protocol`, `sensitive-data.jwt-token`, and `security.xxe`; published reviewed false-positive shapes in `list-rules` and `docs/rules.md`; and updated the `docs/rules.md` inline suppression example to name a live rule.
- **`--generate-baseline` names its own destination** - `--generate-baseline=PATH`, or a following word ending in `.json`, picks the baseline file, as in the other gruff tools; any other following word stays a scan target, so `--generate-baseline src` writes `gruff-baseline.json` and scans `src`. `--generate-baseline-path` still works and warns.

### Fixed

- **`hook --diff` keeps newly added duplicates visible and matches `analyse` baseline ordinals** - Base occurrences are counted rather than deduplicated as a set, and `hook --baseline` uses the exact finding identity computed by `analyse`.
- **Correlated findings without a line share one penalty** - `ScoreCalculator` bills correlated size or complexity findings on one function as one shared penalty even when callers pass line-less findings directly.
- **Invalid `.gitignore` patterns no longer crash scans** - Unusable patterns (such as a lone `!` or trailing backslash) are skipped while the file's other patterns still apply.
- **Relative targets, baselines, and out-of-root config errors resolve from the launch directory** - `analyse ..`, `summary ..`, `report ..`, `--baseline`, `--generate-baseline`, and `--migrate-baseline` resolve relative to the working directory rather than the project root, and out-of-root `--config` failures emit a valid JSON `config-error` envelope instead of a `ValueError` traceback.
- **Machine output no longer leaks host paths, and symbols with `#` no longer abort baselines** - Removed absolute `metadata.projectRoot` values and absolute config paths from JSON/SARIF output, normalized `docs.missing-readme` baseline paths to `README.md`, marked `#`-bearing symbols `baselineStatus: notEligible`, and updated baseline tips to print canonical `--baseline` / `--generate-baseline` flags.

### Known limitations

- **Test, fixture, and example paths are skipped by security and sensitive-data rules by default** - A real secret or insecure call committed under one of those paths will not report; every skip is counted in `suppressions` with `source: "built-in"`.
- **The `cryptography` scan speed-up has no family performance regression suite** - The speed-up from 522 s to 15 s (measured 2026-08-12) ships without a cross-port regression suite in `0.6.0`.
- **Zero findings on the self-scan gate does not measure false-positive rate** - Passing dogfood proves `gruff-py` satisfies its own rules; false-positive rates are measured separately on negative fixtures and external repositories.

## v0.5.0 - 2026-08-16

- **Source-text checks survive Python parse failures** - Invalid Python still runs raw-source rules; parser errors stay fatal and suppressions apply.
- **SSRF sinks now require documented HTTP-client receivers** - Package and submodule imports qualify; app-owned and unimported calls stay quiet.
- **Framework request accessors retain security taint** - Supported Flask, Django, DRF, and Starlette accessors preserve request taint.
- **Module-qualified request receivers taint again** - `flask.request.args` seeds taint when an import binds the module; `other.request` stays quiet.
- **BREAKING: Markdown-link sanitizer trust is now explicit and slot-aware** - Configure exact label and URL sanitizer targets.
- **Weak hashes honour the standard-library non-security opt-out** - Only literal `usedforsecurity=False` suppresses MD5/SHA1 warnings.
- **BREAKING: `init --force` regenerates, never overwrites** - Supported settings carry over; unsafe YAML or TOML is refused untouched.
- **A first-time `init` writes a umask-derived config mode** - Fresh generation no longer emits `0600`; regeneration preserves an existing mode.
- **Unknown per-rule options no longer reach rule execution** - Normal scans warn and drop them; strict config fails on the dotted key.
- **`--fail-on` now states its diagnostic boundary** - It gates findings only; parse errors still exit 2 with `--fail-on none`.
- **Reports rename `Scope` to `Scan context`** - Text, Markdown, and HTML add a `Scoring mode:` line; scripts matching `Scope:` need updating.
- **Cross-module private-function loads now prove liveness** - Real imports keep functions; partial scans suppress unsafe advice.
- **`global` and `nonlocal` rebinds now invalidate the import they overwrite** - Loads after the rebind in that body stop proving liveness.
- **Test and fixture heuristics reject more false positives** - Pytest aliases, package metadata, and sequential digit fixtures classify correctly.
- **PII fixture scanning follows path segments, not substrings** - `integration_tests` still qualifies; `latest` and `test-scan-repos` no longer do.
- **File length counts substantive lines** - Blank lines, comments, and PEP 257 docstrings are free; other strings count. Limits stay fixed.
- **Large source files analyse without tokenizer stalls** - Sources with no `gruff` suppression marker skip tokenization instead of stalling.
- **Scans are slower than 0.4.1** - Whole-project analysis costs time: corpus scans run 15-30% slower and `cryptography` moves from 15.5s to 17.7s.
- **Dashboard compatibility help is honest and remote binds are deliberate** - Public binds need `--allow-public`; no-op flags are disclosed.
- **Boolean naming now matches scalar annotation shapes exactly** - Scalar bools qualify; containers, callables, and mixed unions do not.
- **Boolean predicate vocabulary now follows exact identifier tokens** - Final `alive`/`contains` and standalone `has` qualify.
- **`todo` is no longer a universal placeholder identifier** - Domain names stay quiet; first-token and numbered placeholders still warn.
- **CI inputs are pinned and lock drift fails early** - Actions use verified SHAs; installs use the lock and permissions stay read-only.
- **Destructive-command hook preserves quoted cleanup targets** - Proven local paths with spaces pass; unsafe or unresolved targets fail.
- **Generated rule-catalog facts no longer drift across current docs** - Current docs derive rule and pillar totals from registered definitions.
- **Known limitation: composite scores remain volume-sensitive** - PyGoat scores 58.45 while requests, Flask, and pytest remain below 23.

## v0.4.1 - 2026-06-14

- **New `correctness.unsafe-numeric-coercion`** - Warns on `int()` after weak Unicode digit guards or unbounded float conversion.
- **New `correctness.substring-vocabulary-match`** - Warns when free-text parameters use substring membership against literal vocabularies.
- **New `security.unsanitized-markdown-interpolation`** - Warns when dynamic Markdown link labels or URLs lack a wrapping sanitizer call.
- **New `design.runtime-sys-path-mutation`** - Warns on runtime `sys.path.insert`/`append`, except tests and guarded scripts.
- **New `dead-code.exported-but-unreferenced`** - Full scans flag exports with no real loads; allowlists cover dynamic entry points.
- **Maintenance** - Rule docs moved to `catalog_docs.py`; the catalogue reached 130 rules across 12 pillars.
- **Unknown rule keys warn by default** - `--strict-config` restores hard failures; structural and schema errors always abort.
- **New `migrate-config` command** - Converts legacy YAML, preserves supported settings, previews diffs, and directs TOML users to edit.
- **Fewer module-name mismatch false positives** - Exempts helper-rich modules, value envelopes, private files, and test filenames.

## v0.4.0 - 2026-06-11

- **Corpus-verified false-positive sweep** - Removed 7, 165, and 202 findings from AI-Trader, headroom, and supervision.
- **Security rules are more precise** - SQL needs stronger evidence; constants, credential placeholders, and test PII get safer handling.
- **`extends-production-class` understands test bases** - `*TestCase` and configured `additionalTestBases` count as scaffolding.
- **Project rules report scan scope honestly** - Narrow scans add a partial-context caveat; full-root paths stay full-project.
- **Display filters disclose hidden findings** - Text shows visible and hidden counts; scoring and exit codes still use every finding.
- **Agent hooks support `--exclude-rule`** - Repeatable or comma-separated exclusions alter one run without editing project config.
- **PR review fixes improve precision** - Dynamic SQL, warning assertions, tokenizer fallbacks, constants, and protocol references classify correctly.
- **Maintenance** - Catalog relations moved to `catalog_related.py`; rule docs stamp versions; source prefilters reduce work.

## v0.3.1 - 2026-06-09

- **Agent-hook contract v1** - `gruff-py hook` emits `gruff.hook.v1`, supports baselines and changed ranges, and returns structured errors.
- **Symbol-scoped diffs suppress inherited debt** - File and class findings surface only when their anchor or header is touched.
- **BREAKING: analysis schema is now `gruff.analysis.v2`** - Replace `gruff-py.analysis.v1` in consumers; other schema IDs are unchanged.
- **New `static-analysis-redundant-test` rule** - Flags tests that only restate same-file declarations; dynamic and behavioral cases stay quiet.
- **Text and summary output reshaped** - Adds composite grades and severity totals; non-text formats, identities, and schemas stay unchanged.
- **Quality hook adds focused summaries and self-tests** - Shows capped, severity-sorted changed-line findings and fails soft without a repo root.
- **Maintenance** - Hook CLI moved to `gruffpy.cli_hook`, keeping the main CLI under its file-length limit.

## v0.3.0 - 2026-06-02

- **BREAKING: `complexity.npath` removed** - Delete it from selections and rule config; pinned configs now fail as unknown.
- **BREAKING: `design.god-method` retired** - Remove its suppressions and regenerate baselines; correlated scoring remains.
- **BREAKING: rules use one threshold and severity** - Replace warning/error maps, or rerun `gruff-py init --force`.
- **Changed-region analysis added** - `analyse` supports ranges, refs, diffs, and scopes; hooks use native filtering without baselines.
- **New `check-ignore` command** - Reports whether paths are ignored and why, using analysis semantics and git-like exit codes.
- **JSON adds `ignoredPathDetails`** - Reports each skipped path's source and pattern while retaining `ignoredPaths` and schema IDs.
- **`paths.ignore` is authoritative** - Config ignores apply to walks, explicit files, and diffs; `--include-ignored` cannot override them.
- **Supply-chain security rules added** - Checks action pins, workflow permissions, risky PR flows, URLs, VCS refs, and local dependencies.
- **Sensitive-data rules expanded** - Adds GCP keys, URL credentials, stronger provider tokens, placeholder guards, and reporter leak tests.
- **Noisy rubrics recalibrated** - Tightens naming, tests, waste, and magic numbers; reweights scoring without identity changes.

## v0.2.0 - 2026-05-28

Cross-port `minimumSeverity:` config dimension under the new `gruff-py.config.v0.1` schema, line-insensitive `stableIdentity` field on JSON findings, triage tooling (`summary --group-by=rule`, `list-rules <rule_id>` explain mode, analyse-text volume hint), `docs.missing-*` message reword, and `naming.parameter-type-name` retirement. Summary payload reshaped under the new `gruff.summary.v2` schema. Catalogue drops to 115 rules across 11 pillars. Four breaking changes drive the minor bump.

- **BREAKING: `--fail-on` now defaults to `advisory`** - Set `minimumSeverity.analyse: error` or pass `--fail-on error` for old behavior.
- **BREAKING: summary `pillars` is now a row list** - Replace `.items()` loops with row iteration under `gruff.summary.v2`.
- **BREAKING: configs require `gruff-py.config.v0.1`** - Run `gruff-py init --force` for YAML or add the schema line to TOML.
- **BREAKING: `naming.parameter-type-name` retired** - Remove it from selections and rule config; the catalogue now has 115 rules.
- **Per-project severity gates added** - `minimumSeverity` supports analyse, report, and dashboard; CLI flags still win.
- **Line-insensitive `stableIdentity` added** - JSON findings match across line shifts; fingerprints, SARIF, and schemas are unchanged.
- **Noisy-run triage added** - Summary groups by rule, list-rules explains one rule, and large text analyses link to guidance.
- **`docs.missing-*` messages reframed** - Findings say what needs documentation instead of inviting mechanical filler.
- **Loader errors are visible and format-aware** - Text uses clean stderr; JSON emits diagnostics instead of silent fallback.
- **`init` scaffolds richer config** - Adds per-rule descriptions, preserves key blocks on force, and seeds shared abbreviations.
- **Rule grouping uses worst severity** - Mixed-threshold rules appear at their highest emitted severity in grouped summaries.
- **Dashboard config paths resolve consistently** - Initial thresholds and scans use the same project-relative config path.
- **Allowlist defaults are preserved** - Unrelated user allowlists no longer clear seeded abbreviations or secret previews.

## v0.1.1 - 2026-05-24

Baselines promoted from reserved schema to wired feature. `gruff-py init` for default config scaffolding. Validated manual PyPI publish script. Catalogue still 116 rules across 11 pillars: `modernisation.f-string-candidate` added, `test-quality.testdox-readability` removed. Post-review CLI cleanups. Two breaking changes.

- **BREAKING: `test-quality.testdox-readability` removed** - Delete the rule from YAML or TOML config before upgrading.
- **BREAKING: baseline flags reject positional paths** - Use `--baseline-path` or `--generate-baseline-path`; dashboard placeholders are removed.
- **New `gruff-py init` command** - Writes default config, preserves ignored paths, avoids shadowing other config, and prompts safely.
- **Baseline workflows added** - Read, apply, and atomically generate baselines; legacy schemas work, and partial scans suppress stale warnings.
- **`modernisation.f-string-candidate` rule** - Flags literal `"...".format(...)` calls that can convert to f-strings.
- **`multiple-aaa-cycles` over-fires less** - Data unpacking and narrowing no longer advance Act/Assert state like function calls.
- **Validated PyPI publisher added** - Runs preflight, version, clean-tree, build, verify, and confirmation before PyPI or TestPyPI.
- **Docs and footguns expanded** - Adds CI/output guides, normalizes names and spelling, fixes totals, and records baseline and CLI traps.
- **Baseline I/O hardened** - Improves schema/decode errors, default-path detection, broken-config discovery, and write error handling.
- **Release gates fixed** - Fresh dist cleanup, baseline-free checks, dashboard baseline isolation, and prompt-safe structured output.

## v0.1.0 - 2026-05-23

First public release. Python static analyser modelled on the gruff family, with cross-implementation fingerprint compatibility from day one.

- **116-rule initial catalogue** - Covers size, complexity, maintenance, dead code, naming, docs, security, tests, and design.
- **Output formats** - Text, JSON, HTML, Markdown, GitHub annotations, hotspot, SARIF 2.1.0.
- **Configuration and dashboard** - Local dashboard, YAML/TOML config, and PHP-compatible 16-character baseline fingerprints.
- **Pinned schemas** - `gruff-py.analysis.v1`, `gruff-py.hotspot.v1`, `gruff-py.baseline.v1` (reserved).
- **Pre-release false-positive sweep** - 9 rules tightened against a 53-file dogfood project: 425 → 335 findings (-21%).
