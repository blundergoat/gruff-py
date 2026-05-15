# gruff-py

Python project quality analyser. Walks a project tree, applies rules across
ten quality pillars (size, complexity, maintainability, dead-code, naming,
documentation, security, sensitive-data, test-quality, design), synthesises composite
`design.*` findings where pillars overlap, and emits a scored A-F report. The
`modernisation` pillar is declared but its rule catalogue is still being built.

## Status

`0.1.0-dev` - pre-release. **98 rules across 10 pillars** are wired into the
default registry, available via `RuleRegistry.defaults()`. CLI output (text,
JSON, HTML, Markdown, GitHub annotations, SARIF, hotspot), config loading
(`.gruff.yaml` + `pyproject.toml`), two-axis severity x confidence scoring,
project-level rule execution, and finding fingerprints byte-compatible with
the PHP reference are in place. The cross-implementation JSON byte-equivalence
checker is still pending.

## The gruff family

This is the Python port of an analyser that exists in four languages. The PHP
implementation is canonical; sibling ports in TypeScript and Rust exist but
diverged from PHP on the fingerprint algorithm. This Python port re-aligns
with PHP. Schema strings (`gruff.analysis.v1`, `gruff.baseline.v1`,
`gruff.hotspot.v1`) and finding fingerprints stay byte-for-byte identical
across implementations.

## Quick start

```bash
uv sync
uv run gruff analyse src/
```

The installed distribution is `gruff`; `gruff-py` is the project nickname.

## Sample output

```text
gruff 0.1.0-dev
Format: text
Fail threshold: error

Files
  Discovered: 1
  Parsed: 1

Score
  Composite: C (79.91/100)
  Pillars:
    size: B (84.00) findings=1
    complexity: F (0.00) findings=6
    documentation: F (49.00) findings=4
    design: F (52.00) findings=1
    ...

Findings
  [error] complexity.npath
    src/gruff/source/discovery.py:84
    Function 'SourceDiscovery.discover' has NPATH complexity 650,
    above the error threshold of 500.
  [error] design.god-method
    src/gruff/source/discovery.py:84
    Symbol 'SourceDiscovery.discover' is a god method:
    4 overlapping size/complexity findings.
```

JSON output (`--format json`) emits the `gruff.analysis.v1` schema with
findings, scores, display filters, and run metadata in stable key order -
suitable for diffing across runs and across implementations.

## Report formats

`--format` accepts:

| Format | Use |
|---|---|
| `text` | Local terminal summary |
| `json` | Full `gruff.analysis.v1` payload |
| `html` | Self-contained dark inspection report; add `--report-interactive` for browser filters |
| `markdown` | GitHub-flavoured PR/comment summary |
| `github` | GitHub Actions workflow annotation commands |
| `hotspot` | `gruff.hotspot.v1` file-offender JSON |
| `sarif` | SARIF 2.1.0 code-scanning payload |

Display-only filters are available for every format: `--min-severity`,
`--include-pillar`, `--exclude-pillar`, `--include-rule`, and `--exclude-rule`.
They filter the rendered findings and are recorded under `run.filters`; they do
not change the underlying exit-code calculation.

## Dashboard

`gruff dashboard` starts a local-only browser dashboard on `127.0.0.1:8765`
by default. It serves the same HTML report as `gruff analyse --format html`
inside a full-window iframe with scan controls for project root, paths, fail
threshold, config loading, ignored directories, and interactive finding
filters.

```bash
uv run gruff dashboard src/ --report-interactive
```

Use `--port 0` to let the OS choose an unused port. The dashboard is synchronous
and dependency-free; each refresh reruns the same internal analysis pipeline as
`gruff analyse`.

## Configuration

Two sources, in precedence order: `--config <path>` (CLI flag), `.gruff.yaml`
in the project root, then `[tool.gruff]` in `pyproject.toml`. Defaults come
from `RuleRegistry.defaults()`. Unknown keys reject strictly with a
`config-error` diagnostic (exit `2`).

```yaml
# .gruff.yaml
paths:
  ignore:
    - "tests/fixtures/**"

rules:
  size.file-length:
    thresholds:
      warning: 400
      error: 800
```

The TOML equivalent under `[tool.gruff]`:

```toml
[tool.gruff.paths]
ignore = ["tests/fixtures/**"]

[tool.gruff.rules."size.file-length"]
thresholds = { warning = 400, error = 800 }
```

## Pillars and rule namespaces

| Pillar | Rule namespace | Notes |
|---|---|---|
| `size` | `size.*` | File/function/class length, parameter & attribute counts |
| `complexity` | `complexity.*` | Cyclomatic, cognitive, Halstead, nesting, NPATH |
| `maintainability` | `complexity.maintainability-index` | Single-rule pillar; MI emits here, not under `complexity` |
| `dead-code` | `dead-code.*` and `waste.*` | Unused private symbols, empty bodies, unreachable code |
| `naming` | `naming.*` | Intent-layer naming (gruff owns); PEP 8 case is ruff's job |
| `documentation` | `docs.*` | Docstring presence, param/return/raises consistency, TODO density |
| `security` | `security.*` | Heuristic AST-level dangerous patterns |
| `sensitive-data` | `sensitive-data.*` | Secrets, keys, PHI/PII; runs on text files too |
| `test-quality` | `test-quality.*` | Pytest-aware test smells; 28 default-on + 6 opt-in |
| `design` | `design.*` + composite | Project-level abstraction rule plus synthesized size/complexity overlap findings |
| `modernisation` | declared, not yet populated | Pillar exists in the score model; no rules ship in 0.1.0-dev |

The `Pillar` enum additionally declares `coupling`, `architecture`, and `mutation` as placeholders for future catalogues; they carry no rules and do not appear in score output yet.

## Exit codes & common errors

| Code | Meaning | What to do |
|---|---|---|
| `0` | Clean run; nothing at or above `--fail-on` | — |
| `1` | At least one finding tripped the fail threshold | Inspect findings; lower the threshold with `--fail-on warning` or `--fail-on advisory` to relax |
| `2` | Diagnostic: config error, parse error, or missing path | Re-read the diagnostic message line; unknown keys in `[tool.gruff]` reject strictly |

`--fail-on {error,warning,advisory,none}` selects the threshold. `--no-config`
disables config-file loading. `--include-ignored` walks into default-ignored
directories.

## Cross-implementation compatibility

`gruff.analysis.v1` (analyse JSON), `gruff.baseline.v1` (baseline format), and
`gruff.hotspot.v1` (hotspot schema) are stable
contracts shared across implementations. Finding fingerprints are 16-character
SHA-256 derivatives that reproduce the PHP reference byte-for-byte - including
PHP's slash-escaping defaults during JSON serialisation. Score penalties use
the two-axis severity x confidence weight model: severity 12/4/1, confidence
1.0/0.75/0.5, pillar multiplier x4, file multiplier x5. Grades A/B/C/D/F at
90/80/70/60.
