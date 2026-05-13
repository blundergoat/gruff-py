# Changelog

All notable changes to `gruff-py` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

Foundational scaffolding and the v0.1 rule catalogue.

**Cross-cutting infrastructure:**
- `RuleRegistry` + `Rule` abstract base + per-pillar packages under
  `src/gruff/rule/<pillar>/`.
- Core domain types in `gruff.finding`: `Finding`, `Severity`, `Pillar`,
  `Confidence`, `RuleTier`, `OutputFormat`, `FailThreshold`. All enums are
  `StrEnum`-backed.
- `fingerprint_for()` — byte-compatible with the PHP reference; 16-character
  SHA-256 derivatives. Verified against PHP-generated ground-truth fingerprints.
- `AnalysisConfig` with two-source loading: `--config <path>` flag,
  `.gruff.yaml` in the project root, then `[tool.gruff]` in `pyproject.toml`.
  Unknown keys reject with a `config-error` diagnostic (exit `2`).
- `SourceDiscovery` with default-ignored directory list and an
  `IGNORED_FILENAMES` set covering Python and JS ecosystem lockfiles
  (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `composer.lock`, `Cargo.lock`, `go.sum`).
- `PythonFileParser` (stdlib `ast`, with parent-attaching pre-pass).
- `SourceTextRule` marker base class — rules subclassing it run on
  `.env`/`.toml`/`.yaml`/`.json`/`.ini`/`.conf` text files in addition to Python.
- `ScoreCalculator` with two-axis severity × confidence penalty model
  (severity weights 12/4/1, confidence weights 1.0/0.75/0.5, pillar multiplier
  ×4, file multiplier ×5). A–F grading at 90/80/70/60.
- `CompositeFindingFactory` — post-processes per-unit findings into composite
  `design.god-method` findings when size+complexity overlap on a symbol.
- `AnalysisReport` matching the `gruff.analysis.v1` schema verbatim.
- `text` and `json` reporters. JSON output is byte-compatible with the PHP
  reference's `JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES`-default behaviour
  (4-space indent, slashes escaped, non-ASCII escaped).
- `gruff analyse [paths...]` CLI via Click with `--format`, `--fail-on`,
  `--config`, `--no-config`, `--include-ignored` flags.

**Rules — 97 total across 9 pillars:**
- `size.*` — 7 rules (file/class/function length, parameter & attribute counts).
- `complexity.*` — 6 rules (cyclomatic, cognitive, Halstead volume,
  maintainability index, nesting depth, NPATH). `maintainability-index`
  emits under the `maintainability` pillar.
- `dead-code.*` + `waste.*` — 10 rules (unused private symbols, empty bodies,
  unreachable code, one-line wrappers, redundant variables, unused imports/parameters).
- `naming.*` — 9 rules (intent-layer naming; PEP 8 case style is delegated to
  ruff's `N` rules per ADR-004).
- `docs.*` — 10 rules (presence checks, field-mismatch checks parsed via
  `docstring-parser` per ADR-005, TODO density, missing README).
- `security.*` — 12 rules (eval/exec/compile, unsafe-pickle, SQL concat, weak
  crypto, insecure random, silent except, error suppression, shell injection,
  header injection, disabled SSL verify, variable import, splatted user input).
- `sensitive-data.*` — 9 rules (AWS keys, PEM private keys, JWT, vendor API
  key patterns, database URL passwords, hardcoded `.env` secrets, generic
  high-entropy strings, PHI patterns, PII in test fixtures).
- `test-quality.*` — 34 rules (28 default-on + 6 opt-in / project-config).
  Memoised scope detection via a shared `_test_quality_node_helper`.

**ADRs landed:**
- `ADR-002` size line-counting policy (raw line span, decorator → `end_lineno`).
- `ADR-003` cognitive-complexity algorithm choice (SonarSource v1.4).
- `ADR-003a` composite-finding fingerprint shape.
- `ADR-004` naming pillar boundary (gruff intent / ruff style; disjoint).
- `ADR-005` docstring-style parser pick (`docstring-parser>=0.15,<1`).
- `ADR-006` cross-impl config shape (`.gruff.yaml` + `[tool.gruff]`).

**Test suite:** 668 tests across fingerprint goldens, per-rule logic, pillar
integration fixtures, config loading precedence, and CLI smoke. Memoisation
gate test confirms test-quality rules share a single scope-detection pass per
analyse run.

### Notes

The cross-implementation invariant set (schema strings, fingerprint algorithm,
penalty weights, grade bands) is documented in the README under
"Cross-implementation compatibility". Treat that section as the canonical
description; this changelog only records when those invariants land or move.

<!-- Keep new versions above and prior history below this line. -->
