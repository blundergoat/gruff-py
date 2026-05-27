# Changelog

All notable changes to `gruff-py`. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Public API pre-1.0.

## [0.1.2] - 2026-05-27

Cross-port `minimumSeverity:` config dimension under the new `gruff-py.config.v0.1` schema; `analyse --fail-on` default flips `error` → `advisory`. `docs.missing-*` messages reframed ("needs a brief intent description" rather than "has no docstring"). Additive line-insensitive `stableIdentity` field on JSON findings alongside `fingerprint`. New `summary --group-by=rule`, `list-rules <rule_id>` explain mode, analyse-text volume hint. Summary payload reshaped under new `gruff.summary.v2` schema. `naming.parameter-type-name` retired; catalogue drops to 115 rules.

### Added
- `minimumSeverity:` block + required `schemaVersion: gruff-py.config.v0.1` (ADR-019). Pre-existing configs without `schemaVersion:` rejected on load; `gruff-py init --force` regenerates.
- `stableIdentity` on every JSON finding (ADR-020): line-insensitive companion to `fingerprint`. No schema bump; SARIF + baselines unchanged.
- `gruff.summary.v2` schema with canonical pillar rows (grade/score/applicable/findings/advisory/warning/error/penalty) across text/JSON/Markdown/HTML.
- `summary --group-by=rule` via `AnalysisReport.finding_counts_by_rule()`; `analyse --format text` footer hint at `outputVolumeHintThreshold` findings (default 50).
- `list-rules <rule_id>` explain mode (text + JSON) with `RuleDocs.option_descriptions`, `false_positive_shapes`, and `RELATED_RULES` cross-references.
- `gruff-py init` writes per-rule description comments and preserves the `minimumSeverity:` block byte-for-byte across `--force`.
- ADRs 018 (retire parameter-type-name), 019 (minimumSeverity), 020 (stableIdentity).

### Changed
- **Behaviour:** `analyse --fail-on` default `error` → `advisory`. Set `minimumSeverity.analyse: error` or pass `--fail-on error` to restore.
- **Breaking JSON:** summary `pillars` is now a list of pillar-row dicts (was `{pillar: count}`).
- `docs.missing-*` messages reframed; trigger conditions and fingerprints unchanged.
- `ConfigError` from the loader propagates as clean CLI stderr + exit 1 instead of silently falling back to defaults.

### Removed
- **Breaking:** `naming.parameter-type-name` rule. Pinned configs fail with `Unknown rule id`; remove the entry to upgrade (ADR-018).

### Fixed
- `ConfigLoader._apply_allowlists` no longer clears seeded `accepted_abbreviations` / `allowed_secret_previews` when `allowlists:` is partial.
- Dashboard initial form seed reads the same config file `/scan` reads when `--config` is relative and `--project` differs from CWD.
- `finding_counts_by_rule` reports the worst severity per rule (was first-finding), so `summary --group-by=rule` doesn't understate threshold-based rules.

## [0.1.1] - 2026-05-24

Catalogue still 116 rules across 11 pillars: `modernisation.f-string-candidate`
added, `test-quality.testdox-readability` removed. Baseline support promoted from
reserved schema to a wired feature, plus `gruff-py init`, a manual PyPI publish
script, and the post-review CLI cleanups described below.

### Added

- `gruff-py init` command writes a default `.gruff-py.yaml` mirroring
  `RuleRegistry.defaults()`, with `--force` regeneration that preserves an
  existing `paths.ignore` list and refuses to shadow an alternate config source
  (`.gruff.yaml` or `[tool.gruff-py]` in `pyproject.toml`) unless `--force`.
- Interactive `analyse`/`report`/`summary`/`dashboard` runs offer to generate
  `.gruff-py.yaml` when none is discoverable; the prompt skips on
  `--no-config`/`--no-interaction`/`--quiet`/`--silent`/non-TTY stdin and
  routes both prompt and success message to stderr so structured stdout stays
  clean.
- Baseline read/apply/generate with a dedicated `BaselineOptions` request type,
  atomic file writes, and a `BaselineReport` extension on every analysis report.
  Default baseline `gruff-baseline.json` auto-applies for `analyse`/`report` when
  present; `dashboard` always disables baseline application. Legacy
  `gruff.baseline.v1` JSON is accepted alongside `gruff-py.baseline.v1`.
- `analyse` baseline flags: `--baseline-path PATH`, `--generate-baseline` (writes
  to `gruff-baseline.json`), `--generate-baseline-path PATH`, `--no-baseline`.
  `report` exposes `--baseline-path` and `--no-baseline`.
- `modernisation.f-string-candidate` rule.
- `scripts/publish-pypi.sh` for manual, validated PyPI/TestPyPI publishing with
  preflight, version-agreement, clean-tree, build, verify, and confirmation
  steps. Replaces the previous tag-triggered GitHub Actions workflow.
- `docs/ci-integration.md` and `docs/output-formats.md`; `docs/README.md` index.
- Footgun docs covering baseline auto-application, the prior CLI optional-value
  trap, the rule-removal compatibility break, partial-scope baseline scans,
  and shell `find <dir>` first-run failures, under `.goat-flow/footguns/`.

### Changed

- `test-quality.multiple-aaa-cycles` distinguishes function-call statements
  (which advance the Act/Assert state) from data-unpacking statements
  (`finding = findings[0]`, `payload = json.loads(...)`, dict-comp restructuring,
  `isinstance` narrowing) so it no longer over-fires inside one Assert phase.
- `apply_baseline` accepts a `scan_scope` argument and skips stale-entry
  reporting on `partial-scope` runs, so regenerating from a narrowed scan can
  no longer mislead users into dropping suppressions for unscanned files.
- `BaselineStore.read` lists both accepted schema versions in error output,
  catches `UnicodeDecodeError` as a structured `BaselineError`, and the entry
  payload error mentions both `findings` and legacy `entries` keys.
- `_baseline_source` compares paths by basename so `./gruff-baseline.json` is
  correctly labelled `default` instead of `explicit`.
- `existing_config_source` returns the `pyproject.toml` path when the file
  exists but cannot be parsed, so the init prompt does not silently shadow a
  broken pyproject with a new `.gruff-py.yaml`.
- Both init write paths funnel through a shared helper that converts `OSError`
  to `ClickException`, replacing raw tracebacks.
- `list_rules` docstring documents the `text` alias alongside `table` and
  `json`.
- Documentation filenames standardised to lowercase
  (`docs/configuration.md`, `docs/rules.md`, `docs/releasing.md`,
  `docs/reporting.md`, `docs/dashboard.md`).
- Stale-baseline tip in the text reporter uses `--generate-baseline-path`
  with `shlex.quote`, so the command suggestion is correct for custom paths
  and shell-safe to paste.
- README rule-count table corrected to 116 rules / `test-quality` 33; mixed
  British/American "analyser/analyzer" spelling unified.

### Removed

- **Breaking:** `test-quality.testdox-readability` rule. Projects with this
  rule pinned in `.gruff-py.yaml` or `[tool.gruff-py]` will fail to load with
  `ConfigError: Unknown rule id "test-quality.testdox-readability"`. Remove
  the entry from your config to upgrade.
- **Breaking:** the optional-value `--baseline` and `--generate-baseline`
  options on `analyse`/`report`. Use `--baseline-path <path>` for explicit
  baseline application and `--generate-baseline-path <path>` for an explicit
  write destination; the bare `--generate-baseline` flag still writes to
  `gruff-baseline.json`. The previous shape silently scanned `.` when a path
  was supplied after the option (e.g. `gruff-py analyse --baseline src`).
- Dashboard's compatibility `--baseline` / `--no-baseline` placeholder flags;
  the dashboard now always disables baseline application, so the flags can no
  longer mislead users into thinking they wire through.
- Old `.github/workflows/publish.yml` tag-triggered PyPI workflow.

### Fixed

- `scripts/publish-pypi.sh` `clean_dist` `mkdir -p`s `dist/` before invoking
  `find ... -delete`, so the first publish on a fresh clone no longer fails
  with `find: No such file or directory; exit code 1`.
- `scripts/preflight-checks.sh` self-check passes `--no-baseline` to
  `gruff-py analyse`, so release gating depends on current code state instead
  of whichever `gruff-baseline.json` happens to be present in the repo.
- `command/dashboard_server.py` passes `baseline=BaselineOptions(disabled=True)`
  to `run_analysis(...)`, so dashboard scans no longer silently suppress
  matching findings via a default `gruff-baseline.json`.
- `analyse`/`report`/`summary` no longer corrupt structured stdout when the
  user accepts the interactive init prompt: the prompt and success message
  are routed to stderr.
- Init prompt for `gruff-py dashboard --project <other>` writes to the resolved
  project root instead of the launch directory.

## [0.1.0] - 2026-05-23

First public release.

- 116-rule initial catalogue covering size, complexity, maintainability,
  dead-code, naming, documentation, security, sensitive-data, test-quality,
  and design signals.
- Outputs: text, JSON, HTML, Markdown, GitHub annotations, hotspot, SARIF 2.1.0.
- Local dashboard; `.gruff-py.yaml` / `[tool.gruff-py]` config; PHP-compatible 16-char fingerprints.
- Schemas pinned: `gruff-py.analysis.v1`, `gruff-py.hotspot.v1`, `gruff-py.baseline.v1` (reserved).
- Pre-release false-positive sweep across 9 rules: 425 → 335 findings (-21%) on a 53-file dogfood project.
