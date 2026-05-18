# Changelog

All notable changes to `gruff-py` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The public API is still pre-1.0, so compatibility promises are limited to the
schema and fingerprint contracts called out below.

## [Unreleased]

### Notes

- Final public release still needs a version decision in `pyproject.toml`
  (`0.1.0.dev0` versus `0.1.0`) and a license decision if this repository will
  be open source.

## [0.1.0] - 2026-05-15

### Added

- `gruff analyse [paths...]` Click command.
- gruff-php-compatible top-level CLI surface with `completion`, `help`,
  `list`, `list-rules`, `report`, and `summary` commands.
- Root CLI menu rendering now follows the gruff-php/Symfony layout and ANSI
  colour treatment.
- Symfony-style global options accepted by every command:
  `--silent`, `--quiet`, `--version`, `--ansi` / `--no-ansi`,
  `--no-interaction`, and `--verbose`.
- `gruff dashboard [paths...]` local browser dashboard.
- Optional configuration from `--config`, `.gruff-py.yaml`, or `[tool.gruff-py]`.
- Strict config validation with diagnostics for unknown keys.
- Source discovery for Python files and selected text/config files.
- Default ignores for generated, dependency, cache, and VCS directories.
- Python AST parsing with parent links for rule implementations.
- Project-level rule seam for cross-file analysis.
- Display-only finding filters for report output.
- Composite `design.god-method` findings when size and complexity overlap.
- `gruff.analysis.v1` JSON report payload.
- `gruff.hotspot.v1` hotspot payload.
- PHP-compatible 16-character finding fingerprints.
- Two-axis scoring model using severity and confidence weights.
- A-F composite, pillar, and file grades.
- Self-contained dark HTML report with optional browser filters.
- Markdown report output.
- GitHub Actions annotation output.
- SARIF 2.1.0 output.
- Local dashboard shell matching the gruff-php dashboard pattern.

### Rule Catalogue

- 98 rules are registered in `RuleRegistry.defaults()`.
- Active pillars in `0.1`: `size`, `complexity`, `maintainability`,
  `dead-code`, `naming`, `documentation`, `security`, `sensitive-data`,
  `test-quality`, and `design`.
- Rule counts by pillar:
  - `size`: 7
  - `complexity`: 5
  - `maintainability`: 1
  - `dead-code`: 10
  - `naming`: 9
  - `documentation`: 10
  - `security`: 12
  - `sensitive-data`: 9
  - `test-quality`: 34
  - `design`: 1
- Three test-quality rules are opt-in by default:
  `test-quality.mocking-domain-object`,
  `test-quality.multiple-aaa-cycles`, and
  `test-quality.testdox-readability`.

### Compatibility Contracts

- Schema string: `gruff.analysis.v1`.
- Baseline schema string reserved for cross-implementation compatibility:
  `gruff.baseline.v1`.
- Hotspot schema string: `gruff.hotspot.v1`.
- Fingerprints intentionally reproduce gruff-php's hash input behaviour,
  including escaped forward slashes before hashing.
- JSON report rendering uses four-space indentation and does not escape forward
  slashes in output.

### Documentation

- Public README.
- Changelog.
- Configuration guide.
- Reporting guide.
- Dashboard guide.
- Rule catalogue overview.
- Contributing guide.
- Security policy.
- Support guide.
- Release checklist.
- Proprietary license notice.

### Verified

- `uv run ruff check src tests`
- `uv run ruff format --check src tests`
- `uv run mypy src`
- `uv run pytest`
