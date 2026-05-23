# gruff-py

`gruff-py` is the Python implementation of **gruff**, an opinionated project
quality analyser. It walks Python projects, applies a broad rule catalogue, and
emits scored reports for local review, CI, code scanning, and a browser
dashboard.

It is heuristic static analysis. Use it beside tools such as `ruff`, `mypy`,
`pytest`, and security scanners, not as a replacement for them.

## Status

`0.1.0` is the first public release.

- Python 3.11+
- 116 rules across 10 active quality pillars
- Text, JSON, HTML, Markdown, GitHub annotation, hotspot, and SARIF reports
- Local dashboard served from `127.0.0.1` by default
- `.gruff-py.yaml` and `[tool.gruff-py]` configuration
- PHP-compatible finding fingerprints
- Python import package `gruffpy` with a typed package marker via `py.typed`
- MIT licensed (see [`LICENSE.md`](LICENSE.md))

## Install

From this repository:

```bash
uv sync
./bin/gruff-py --help
```

The package entry point is `gruff-py`, so `uv run gruff-py --help` is
equivalent after `uv sync`.

After the package is published:

```bash
pipx install gruff-py
gruff-py --help
```

## Quick Start

Analyse a project:

```bash
uv run gruff-py analyse src/
```

Emit JSON for automation:

```bash
uv run gruff-py analyse src/ --format json --fail-on error > gruff.json
```

Emit SARIF for code scanning:

```bash
uv run gruff-py analyse src/ --format sarif --fail-on none > gruff.sarif
```

Create a standalone HTML report:

```bash
uv run gruff-py analyse src/ --format html --report-interactive > gruff-report.html
```

Run the local dashboard:

```bash
uv run gruff-py dashboard src/ --report-interactive
```

Then open:

```text
http://127.0.0.1:8765/
```

## CLI

```bash
gruff-py [GLOBAL OPTIONS] <command>
gruff-py analyse [OPTIONS] [PATHS]...
gruff-py report [OPTIONS] [PATHS]...
gruff-py summary [OPTIONS] [PATHS]...
gruff-py list-rules [OPTIONS]
gruff-py dashboard [OPTIONS] [PATHS]...
gruff-py completion [SHELL]
```

Global options mirror the gruff-php CLI surface: `--silent`, `--quiet`,
`--version`, `--ansi` / `--no-ansi`, `--no-interaction`, and `--verbose`.

Common `analyse` and `report` options:

| Option | Meaning |
|---|---|
| `--format text` | Terminal summary, the default |
| `--format json` | Full `gruff-py.analysis.v1` payload |
| `--format html` | Self-contained dark HTML report |
| `--format markdown` | Pull-request or issue comment summary |
| `--format github` | GitHub Actions annotation commands |
| `--format hotspot` | `gruff-py.hotspot.v1` file offender JSON |
| `--format sarif` | SARIF 2.1.0 code-scanning output |
| `--fail-on error` | Exit non-zero for findings at or above the threshold |
| `--no-config` | Ignore `.gruff-py.yaml` and `[tool.gruff-py]` |
| `--include-ignored` | Scan default-ignored directories and `.gitignore` exclusions |
| `--min-severity warning` | Display only warning/error findings |
| `--include-pillar documentation` | Display only selected pillar findings |
| `--exclude-rule docs.missing-function-docstring` | Hide selected rule findings |

Additional commands:

| Command | Meaning |
|---|---|
| `gruff-py report --format html --output gruff.html` | Render an HTML or JSON report to a file or stdout |
| `gruff-py summary --format text` | Print compact per-pillar, top-rule, and top-file counts |
| `gruff-py list-rules --format json` | Print registered rule metadata |
| `gruff-py list` | List available commands |
| `gruff-py help analyse` | Display command help |
| `gruff-py completion bash` | Dump a shell completion script |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Run completed and no finding reached `--fail-on` |
| `1` | At least one finding reached `--fail-on` |
| `2` | Input, parse, or configuration diagnostic |

## Configuration

Config is optional. Precedence is:

1. `--config <path>`
2. `.gruff-py.yaml` in the project root
3. `[tool.gruff-py]` in `pyproject.toml`
4. Built-in defaults

Example `.gruff-py.yaml`:

```yaml
paths:
  ignore:
    - "tests/fixtures/**"

selection:
  excludeRules:
    - docs.missing-module-docstring

rules:
  size.file-length:
    threshold: 900
    severity: error
```

See [Configuration](docs/CONFIGURATION.md) for the full shape.

## Quality Pillars

gruff-py scores findings across these active pillars:

- `size`
- `complexity`
- `maintainability`
- `dead-code`
- `naming`
- `documentation`
- `security`
- `sensitive-data`
- `test-quality`
- `design`

`modernisation`, `coupling`, `architecture`, and `mutation` are reserved schema
or future catalogue names. They do not all have shipping rules in `0.1`.

See [Rules](docs/RULES.md) for the rule catalogue.

## Reports And Dashboard

- [Reports](docs/REPORTING.md) explains every output format and CI use case.
- [Dashboard](docs/DASHBOARD.md) documents the local browser dashboard.

The JSON schema string is `gruff-py.analysis.v1`; hotspot output uses
`gruff-py.hotspot.v1`. Finding fingerprints are 16-character SHA-256 derivatives
kept compatible with the PHP implementation. SARIF is rendered from the same
native report data without changing native schemas or fingerprints; SARIF result
fingerprints use `partialFingerprints.gruffFingerprint`.

## Development

```bash
uv sync --extra dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest
```

The Makefile mirrors these commands:

```bash
make check
```

Note that `make check` uses the `lint` target, which runs `ruff check --fix`.
Use the explicit commands above when you need non-mutating release verification.

### Performance harness

`scripts/test-performance.sh` runs a fixed workload matrix (cold-start,
analyse on `src/`/`tests/`, reporter variants, synthetic 100/1000-file
fixtures) with median/p95/min/max wall-clock, peak RSS via
`/usr/bin/time -v`, and per-rule cost attribution from `cProfile`. Baselines
live under `scripts/performance-baselines/<host>.json`; pass `--baseline` to
fail the script on regressions.

```bash
make perf-quick    # CI smoke: cold-start + analyse-src vs baseline
make perf          # full suite vs baseline
make perf-baseline # overwrite the linux-x86_64 baseline with the current run
```

## Project Docs

- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security](SECURITY.md)
- [Support](SUPPORT.md)
- [Release checklist](docs/RELEASING.md)
- [License](LICENSE.md)

## Author

Built by [Matthew Hansen](https://www.blundergoat.com/about).

## License

[MIT](LICENSE)
