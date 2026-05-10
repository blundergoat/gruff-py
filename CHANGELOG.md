# Changelog

All notable changes to `gruff-py` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial port from [`gruff-php`](../gruff-php). Foundational architecture mirrors
  `gruff-php`'s modular layout: `RuleRegistry` + `Rule` abstract base + per-pillar
  packages under `src/gruff/rule/<pillar>/`.
- Core domain types in `gruff.finding`: `Finding`, `Severity`, `Pillar`,
  `Confidence`, `RuleTier`, `OutputFormat`, `FailThreshold`. All enums are
  `StrEnum`-backed.
- `fingerprint_for()` — byte-compatible with `gruff-php`'s
  `Finding::fingerprint()` (PHP `json_encode` default flags reproduced including
  `\/` slash-escaping). Verified against 5 PHP-generated ground-truth fingerprints.
- `AnalysisConfig` loaded from `pyproject.toml` `[tool.gruff]` with strict schema
  (unknown keys reject with a `config-error` diagnostic → exit 2).
- `SourceDiscovery` with verbatim default-ignored directories plus Python-specific
  additions (`__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox`,
  `.venv`, `venv`, `htmlcov`).
- `PythonFileParser` using stdlib `ast`, with parent-attaching pre-pass for rules
  that need to walk to enclosing scopes.
- Scoring: `ScoreCalculator` implements the two-axis severity × confidence penalty
  model from `gruff-php` (severity weights 12/4/1, confidence weights 1.0/0.75/0.5,
  pillar multiplier ×4, file multiplier ×5). A-F grading at 90/80/70/60.
- `AnalysisReport` matching the `gruff.analysis.v1` schema verbatim.
- `text` and `json` reporters. JSON output is byte-compatible with `gruff-php`'s
  `JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES` (4-space indent, slashes unescaped,
  non-ASCII escaped).
- `gruff analyse [paths...]` CLI via Click with `--format`, `--fail-on`,
  `--config`, `--no-config`, `--include-ignored` flags.
- First rule: `size.file-length` (default thresholds: warning=400, error=800).
- Test suite: 22 tests across fingerprint goldens, rule logic, and CLI smoke.

### Notes
- Schema strings (`gruff.analysis.v1`, `gruff.baseline.v1`, `gruff.hotspot.v1`)
  are the cross-implementation contract and must remain identical to the
  `gruff-php` canonical implementation.
- Fingerprint algorithm intentionally differs from `gruff-ts` and `gruff-rs`
  (which used a simpler NUL-joined SHA-256); both of those ports diverged from
  `gruff-php`. `gruff-py` follows `gruff-php`.

<!-- Keep new versions above and prior history below this line. -->
