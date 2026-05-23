# Changelog

All notable changes to `gruff-py` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The public API is still pre-1.0, so compatibility promises are limited to the
schema and fingerprint contracts called out below.

## [Unreleased]

## [0.1.0] - 2026-05-23

First public release.

### Fixed

False-positive precision sweep from the 2026-05-23 healthkit/strands_agents
dogfood scan (53 Python files, 425 baseline findings). Total reduction:
**425 → 335** (-21%) across nine rules; no rule's contract, severity, or
fingerprint inputs changed.

- `waste.unused-import` no longer flags `from __future__ import …`
  directives (PEP 236 / 563 markers have no runtime name to reference).
- `waste.empty-class` no longer flags empty subclasses of `Exception` /
  `BaseException` or any base whose name ends in `Error` / `Exception` /
  `Warning` — empty discriminable-exception types are idiomatic Python.
- `naming.parameter-type-name` accepts `websocket`, `req`, `request`,
  `ws`, `msg` as canonical parameter names regardless of annotation —
  the rule no longer recommends `web_socket` for FastAPI / Starlette /
  `websockets` handler params.
- `docs.stale-param-doc` strips leading `*` / `**` from docstring
  parameter entries before matching the signature, so documented
  `*args` / `**kwargs` no longer report as stale.
- `naming.boolean-prefix` exempts UPPER_SNAKE module-level constants
  (`ENABLE_PROMPT_CACHE: bool = True`), pydantic `BaseModel`,
  `RootModel`, `TypedDict`, and `@dataclass` fields — schema field
  names are part of the JSON / API contract.
- `naming.boolean-prefix` allowlist broadened to recognise `looks_`
  prefix and `_affirms` / `_declines` / `_matches` suffixes as
  verb-shaped English predicates.
- `size.public-method-count` and `size.attribute-count` exempt
  `unittest.TestCase` subclasses, pytest `Test*` name-prefix classes,
  framework-base classes (`TypedDict`, `BaseModel`, `NamedTuple`,
  `Protocol`, `ABC`, Enum-like), and `@dataclass` shells — test
  classes and schema classes are not "unfocused" by virtue of having
  many slots.
- `docs.missing-function-docstring` exempts nested functions whose
  name is referenced at most once inside the enclosing function —
  one-shot regex callbacks, SSE `event_generator` patterns, and
  inner mock-method stubs.
- `test-quality.sut-not-called` treats reads of any module-level bound
  name (imports plus module-level `NAME = …` / `NAME: T = …`
  assignments) and attribute access to `model_fields`,
  `__annotations__`, `__fields__`, or `model_config` as SUT touches.
  Schema-contract and prompt-regression tests no longer false-fire.
  Test-framework module imports (`pytest`, `unittest`, `mock`,
  `unittest.mock`) are excluded from the SUT-name set so the rule
  still catches tests that only invoke framework helpers.

### Added

- `gruff-py analyse [paths...]` Click command.
- gruff-php-compatible top-level CLI surface with `completion`, `help`,
  `list`, `list-rules`, `report`, and `summary` commands.
- Root CLI menu rendering follows the gruff-php/Symfony layout and ANSI
  colour treatment.
- Symfony-style global options accepted by every command:
  `--silent`, `--quiet`, `--version`, `--ansi` / `--no-ansi`,
  `--no-interaction`, and `--verbose`.
- `gruff-py dashboard [paths...]` local browser dashboard.
- Optional configuration from `--config`, `.gruff-py.yaml`, or `[tool.gruff-py]`.
- Strict config validation with diagnostics for unknown keys.
- Source discovery for Python files and selected text/config files.
- Default ignores for generated, dependency, cache, and VCS directories,
  plus honouring `.gitignore` exclusions.
- Python AST parsing with parent links for rule implementations.
- Project-level rule seam for cross-file analysis.
- Display-only finding filters for report output.
- Composite `design.god-method` findings when size and complexity overlap.
- `gruff-py.analysis.v1` JSON report payload.
- `gruff-py.hotspot.v1` hotspot payload.
- PHP-compatible 16-character finding fingerprints.
- Two-axis scoring model using severity and confidence weights.
- A-F composite, pillar, and file grades.
- Self-contained dark HTML report with optional browser filters.
- Markdown report output.
- GitHub Actions annotation output.
- SARIF 2.1.0 output.
- Local dashboard shell matching the gruff-php dashboard pattern.
- Shared `is_test_class()` helper in `gruffpy.rule._python_dynamism`
  covering both `unittest.TestCase` subclasses and pytest `Test*`
  name-prefix collection.
- `BaseModel` and `RootModel` recognised as framework bases by
  `has_framework_base()`.

### Rule Catalogue

- 116 rules are registered in `RuleRegistry.defaults()`.
- Active pillars in `0.1`: `size`, `complexity`, `maintainability`,
  `dead-code`, `naming`, `documentation`, `security`, `sensitive-data`,
  `test-quality`, and `design`.
- Rule counts by pillar:
  - `size`: 7
  - `complexity`: 5
  - `maintainability`: 1
  - `dead-code`: 10
  - `naming`: 10
  - `documentation`: 13
  - `security`: 26
  - `sensitive-data`: 9
  - `test-quality`: 34
  - `design`: 1
- Four rules are opt-in by default:
  `naming.abbreviation`,
  `test-quality.mocking-domain-object`,
  `test-quality.multiple-aaa-cycles`, and
  `test-quality.testdox-readability`.

### Compatibility Contracts

- Schema string: `gruff-py.analysis.v1`.
- Baseline schema string reserved for cross-implementation compatibility:
  `gruff-py.baseline.v1`.
- Hotspot schema string: `gruff-py.hotspot.v1`.
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
- Rule catalogue overview generated from the registry.
- Contributing guide.
- Security policy.
- Support guide.
- Release checklist.
- MIT license.

### Verified

- `uv run ruff check src tests`
- `uv run ruff format --check src tests`
- `uv run mypy src`
- `uv run pytest`
