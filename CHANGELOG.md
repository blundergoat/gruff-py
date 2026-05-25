# Changelog

All notable changes to `gruff-py`. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Public API pre-1.0.

## [0.1.2] - 2026-05-25

Catalogue drops to 115 rules across 11 pillars after retiring
`naming.parameter-type-name`. Summary output gains a canonical pillar-row shape
(grade, score, applicable, findings, advisory, warning, error, penalty) across
text, JSON, Markdown, and HTML, declared under the new cross-implementation
`gruff.summary.v2` schema. `gruff-py init` now emits a `rules:` section with one
description comment per rule, and `accepted_abbreviations` ships seeded with the
gruff-rs/gruff-ts default set.

### Added

- `gruff.summary.v2` schema declared on the JSON summary payload via the new
  `SUMMARY_SCHEMA_VERSION` constant in `src/gruffpy/analysis/schema.py`
  (previously the payload carried no `schemaVersion` field). The namespace
  intentionally omits the `-py` suffix so the schema can be shared with
  sibling gruff implementations.
- Canonical pillar rows in text, JSON, Markdown, and HTML summaries: each row
  exposes `pillar`, `grade`, `score`, `applicable`, `findings`, `advisory`,
  `warning`, `error`, and `penalty`, sorted findings DESC then pillar ASC, and
  sourced from `report.score.pillars` when present (falling back to per-finding
  counts otherwise).
- Per-rule description comments above each entry in the `rules:` section of
  the `.gruff-py.yaml` written by `gruff-py init`. The renderer splits into a
  scaffold step (`yaml.safe_dump` on static fields) and a rules step
  (per-entry `yaml.safe_dump` plus a leading `# <description>` line) so YAML
  formatting stays consistent while comments survive round-trips.
- Default `accepted_abbreviations` seed on `AnalysisConfig`: `age, app, db,
  fs, id, io, key, log, max, min, now, raw, rx, tx, ui, url`. Matches the
  gruff-rs/gruff-ts runtime defaults; project-specific vocabulary should
  still be appended via user config rather than added here.
- `ADR-018-retire-naming-parameter-type-name.md` documenting the retirement
  rationale (false-positive rate against PEP 8's silence on parameter naming,
  maintenance burden) and guidance for any future re-implementation.
- Footgun doc covering stale `__pycache__/*.pyc` after deleting a rule
  module: the deleted rule keeps registering until caches are cleared.
  Concrete recovery steps under `.goat-flow/footguns/setup.md`.
- Pattern doc covering the split YAML rendering approach under
  `.goat-flow/patterns/configuration.md`.
- `tests/unit/reporting/test_reporters.py` coverage for the canonical
  seven-column markdown and HTML pillar tables.

### Changed

- **Breaking JSON shape:** `pillars` in the summary payload is now a list of
  pillar-row dicts (was `{pillar: count}`). Consumers iterating `pillars.items()`
  must switch to iterating the list and reading `row["pillar"]` / `row["findings"]`.
- Text summary's `Per pillar:` block is renamed to `Pillars` and rows use
  fixed-width columns with grade and score; the previous `name: count` form
  is gone.
- HTML reporter replaces the `pillar-card` grid with a `<table class="pillar-list">`
  carrying the seven canonical columns; section heading changes from
  `pillar grades` to `pillars`.
- `_summary_payload` and `_summary_text` in `src/gruffpy/cli.py` delegate row
  assembly to new helpers `_summary_pillar_rows` and `_format_pillar_text_rows`.
- `naming.short-variable` docstring no longer references the retired
  `naming.parameter-type-name` rule.
- `AnalysisConfig.with_accepted_abbreviations` docstring updated to mention
  only `naming.abbreviation`.
- `tests/integration/test_cli_smoke.py::test_cli_summary_json_is_compact_digest`
  and `::test_cli_summary_text_includes_path_and_elapsed` carry Google-style
  docstrings describing the invariant under test and the `tmp_path` /
  `monkeypatch` fixtures.
- `tests/unit/reporting/test_reporters.py::test_markdown_reporter_pillars_table_uses_pillar_score_counts`
  carries a one-line rationale docstring.
- Pillar-column position assertions in
  `test_cli_summary_text_includes_path_and_elapsed` now include the offending
  line as the assertion message, and a redundant `findings=` membership check
  (already enforced by the filtering comprehension) was removed.

### Removed

- **Breaking:** `naming.parameter-type-name` rule. Projects pinning this rule
  in `.gruff-py.yaml` or `[tool.gruff-py]` will fail to load with
  `ConfigError: Unknown rule id "naming.parameter-type-name"`. Remove the
  entry from your config to upgrade. See ADR-018 for the full rationale.
- Rule catalogue drops to 115 (`naming` pillar to 9). `docs/rules.md` is
  regenerated; the rule's detailed entry is gone and the `.gruff-py.yaml`
  template no longer lists it under `selection.rules` or the per-rule
  options block.
- Old HTML grid-style pillar layout and the `_pillar_card` helper, superseded
  by the canonical table.

### Fixed

- `ConfigLoader._apply_allowlists` no longer clobbers seeded
  `accepted_abbreviations` / `allowed_secret_previews` defaults when the
  user's `allowlists:` table omits those keys. Previously the loader called
  `with_accepted_abbreviations(())` / `with_allowed_secret_previews(())`
  unconditionally, so any config that defined `allowlists:` for an unrelated
  purpose (e.g. only `secretPreviews` or only `deadCode`) silently cleared
  the new abbreviation seed, making `naming.abbreviation` stricter than
  `AnalysisConfig.from_registry()` and `gruff-py init` output. The loader
  now only applies an allowlist when its key is present in the user's
  section. New coverage in
  `tests/unit/config/test_accepted_abbreviations_loader.py`.
- `_apply_allowlists` was split into `_validate_string_list_allowlists` and
  `_apply_present_allowlists` to keep NPATH complexity below the project's
  500-path error threshold after the conditional-application change.
- Self-dogfood gate (`gruff-py analyse src tests --fail-on advisory`):
  cleared the ten remaining test-quality advisories in `test_cli_smoke.py`
  (`eager-test`, `loop-in-test`, `magic-number-assertion`) and
  `test_reporters.py` (`magic-number-assertion`, `multiple-aaa-cycles`)
  with explicit `# gruff: disable-file` / `disable-next` directives carrying
  per-rule rationale at each suppression site.

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
