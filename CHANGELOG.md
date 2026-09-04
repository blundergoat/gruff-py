# Changelog

All notable changes to `gruff-py`. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org) with the pre-1.0 caveat: while the project is on `0.MINOR.PATCH`, a minor bump (`0.1.x → 0.2.0`) is permitted to break. Every breaking change carries a `BREAKING:` marker and a migration path regardless of which component moves; the only thing pre-1.0 relaxes is the version-number signal.

## Unreleased

- **BREAKING: every score changes - the family adopts one normalized scoring formula** - A pillar is now `floor + (100 - floor) / (1 + density / densityScale)`, where `density` is the pillar's summed severity-by-confidence weight divided by the number of Python files that were actually evaluated. Scores no longer track project size: duplicating a project leaves its grade unchanged, where before it fell. The severity and confidence weights are unchanged, so the movement is the formula, not a re-weighting. Grade boundaries stay at A>=90, B>=80, C>=70, D>=60, because an even five-way split of the new range reproduces them exactly.
- **BREAKING: the composite can be null, and so can a pillar or file grade** - `score.composite.{{score,grade}}` are `null` when the run evaluated nothing at all: an empty directory, or one whose every Python file failed to parse, previously reported a perfect `100` and grade `A`. Every human view renders `Composite: n/a (nothing evaluated)` in that case.
- **`score.evaluatedFiles` and `score.scoredPillars` are published** - The scoring denominator and the pillar set it was drawn from are now in the envelope, so any consumer can reproduce the composite without guessing which file count it used. `evaluatedFiles` counts Python files that survived discovery; it is deliberately not the analysed-file total, which also counts the text inputs the raw-text rules read.
- **Per-file scores follow the same curve as the project** - `score.topOffenders[].score` is the ratified curve over that file's own weighted findings, and each row now publishes its raw `penalty`, so file ranking and project grading can no longer disagree about the same code.
- **BREAKING: `score.pillars[].penalty` is the raw weight** - It was the summed weight multiplied by 4 for a pillar and 5 for a file; both multipliers belonged to the retired absolute-sum formula and are gone. A pillar with one high-confidence error now publishes `penalty: 12`, not `48`.
- **Scores round half away from zero** - Python's built-in `round` breaks ties to even, so a score of exactly 53.125 became 53.12 here while the four sibling ports produced 53.13. Ties now round away from zero in every port.
- **BREAKING: machine JSON uses `gruff.analysis.v3` and `gruff.summary.v3`** - Replace v2 consumers: read ignored and missing paths under `paths`, the composite from `score.composite.{score,grade}`, changed-region counts from `summary.suppressedFindings` and `diff.filteredFindings`, and Python-only run data from `run.extensions.py.run`; `summary --format json` is the analysis document with only top-level `findings` removed. Fingerprints, stable identities, score values, baseline matching, and exit decisions are unchanged. This coordinated pre-1.0 family break has no v2 writer or deprecation window so every port releases one machine contract.
- **BREAKING: default scans use the family fallback policy** - Non-VCS fallbacks now defer to any governing `.gitignore`, committed control metadata stays scannable, and explicit supported files bypass Git and fallback exclusions. Python retains its named cache and environment exceptions; eligible lockfiles are no longer dropped by filename, while VCS internals remain blocked.
- **Bounded deep scans retain safety coverage** - Python sources above 20,000 lines or 2,000,000 bytes keep size, sensitive-data, and config checks while skipping AST and other deep work. `deepScanBudget` is configurable, `--deep-scan-budget LINES:BYTES|off` wins on every scan surface, and a non-fatal `bounded-deep-scan` diagnostic publishes both counts, both limits, and override provenance.
- **New `sensitiveExclusions:` config section** - The only way to silence a `sensitive-data.*` finding. Each entry names one rule id, one project-relative path, an optional symbol, and a required reason; a wildcard rule, a pillar selector, an unknown or non-sensitive rule, an absolute, traversing or globbed path, a missing rationale, a duplicate scope, and any message- or value-matching key each stop the run with a diagnostic naming the entry index and the key. Entries are written by hand; no preview or matched value ever becomes one.
- **Analysis and summary JSON expose `suppressions` audit rows** - Both v3 documents include one `{index, rule, paths, reason, suppressed}` row per configured exclusion, including entries that matched nothing; `symbol` appears only when configured, and text analysis prints the same total under `Sensitive exclusions`.
- **`summary` text states its suppressed total** - The text view carries the same `Sensitive exclusions` section as `analyse`, below the canonical `Composite:` and `Findings:` block; `summary --format json` carries the same v3 `suppressions` audit array.
- **Heuristic rules explain exceptions** - `list-rules` JSON and generated docs include reviewed false-positive shapes and mitigations.
- **BREAKING: composite scores move because the divisor no longer changes between runs** - The composite averaged only the pillars a run happened to produce findings for plus a fixed ten, so `correctness` and `modernisation` joined the average only when they had findings and dropped out when the last one was fixed. Fixing a finding could therefore *lower* the score: a measured run fell from 80.18 (B) to 79.00 (C) when two `modernisation` findings were resolved. All twelve pillars a built-in rule can emit are now always scored, so the divisor is 12 on every run and fixing a finding can never reduce the composite. Every composite and grade shifts upward slightly; per-pillar scores, penalties, fingerprints, stable identities, baseline matching, and exit decisions are unchanged. Regenerate any stored baseline grade or threshold that was tuned against the old value.

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
