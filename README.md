# gruff-py

Python project quality analyser. Walks a project tree, applies rules across
nine quality pillars (size, complexity, maintainability, dead-code, naming,
documentation, security, sensitive-data, test-quality), synthesises composite
`design.*` findings where pillars overlap, and emits a scored A–F report. The
`modernisation` pillar is declared but its rule catalogue is still being built.

## Status

`0.1.0-dev` — pre-release. **97 rules across 9 pillars** are wired into the
default registry, available via `RuleRegistry.defaults()`. CLI output (text,
JSON), config loading (`.gruff.yaml` + `pyproject.toml`), two-axis severity ×
confidence scoring, and finding fingerprints byte-compatible with the PHP
reference are in place. The richer reporter set (HTML, Markdown, GitHub
annotations, SARIF, hotspot) and the cross-implementation JSON
byte-equivalence checker are deferred.

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
findings, scores, and run metadata in stable key order — suitable for
diffing across runs and across implementations.

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
| `design` | composite, no per-unit rule | Synthesised when size+complexity overlap on a symbol |
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
`gruff.hotspot.v1` (hotspot schema; reporter not yet shipped) are stable
contracts shared across implementations. Finding fingerprints are 16-character
SHA-256 derivatives that reproduce the PHP reference byte-for-byte — including
PHP's slash-escaping defaults during JSON serialisation. Score penalties use
the two-axis severity × confidence weight model: severity 12/4/1, confidence
1.0/0.75/0.5, pillar multiplier ×4, file multiplier ×5. Grades A/B/C/D/F at
90/80/70/60.
