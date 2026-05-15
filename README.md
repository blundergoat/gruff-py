# gruff-py

`gruff-py` is the Python implementation of **gruff**, an opinionated project
quality analyser. It walks Python projects, applies a broad rule catalogue, and
emits scored reports for local review, CI, code scanning, and a browser
dashboard.

It is heuristic static analysis. Use it beside tools such as `ruff`, `mypy`,
`pytest`, and security scanners, not as a replacement for them.

## Status

`0.1.0.dev0` is the release-candidate line for the public `0.1` release.

- Python 3.11+
- 98 rules across 10 active quality pillars
- Text, JSON, HTML, Markdown, GitHub annotation, hotspot, and SARIF reports
- Local dashboard served from `127.0.0.1` by default
- `.gruff.yaml` and `[tool.gruff]` configuration
- PHP-compatible finding fingerprints and schema strings
- Typed package marker via `py.typed`

The project metadata currently declares a proprietary license. Replace
`LICENSE.md` and `pyproject.toml` before publishing as open source.

## Install

From this repository:

```bash
uv sync
./bin/gruff-py --help
```

The package entry point is still `gruff`, so `uv run gruff --help` is
equivalent after `uv sync`.

After the package is published:

```bash
pipx install gruff
gruff --help
```

## Quick Start

Analyse a project:

```bash
uv run gruff analyse src/
```

Emit JSON for automation:

```bash
uv run gruff analyse src/ --format json --fail-on error > gruff.json
```

Create a standalone HTML report:

```bash
uv run gruff analyse src/ --format html --report-interactive > gruff-report.html
```

Run the local dashboard:

```bash
uv run gruff dashboard src/ --report-interactive
```

Then open:

```text
http://127.0.0.1:8765/
```

## CLI

```bash
gruff [GLOBAL OPTIONS] <command>
gruff analyse [OPTIONS] [PATHS]...
gruff report [OPTIONS] [PATHS]...
gruff summary [OPTIONS] [PATHS]...
gruff list-rules [OPTIONS]
gruff dashboard [OPTIONS] [PATHS]...
gruff completion [SHELL]
```

Global options mirror the gruff-php CLI surface: `--silent`, `--quiet`,
`--version`, `--ansi` / `--no-ansi`, `--no-interaction`, and `--verbose`.

Common `analyse` and `report` options:

| Option | Meaning |
|---|---|
| `--format text` | Terminal summary, the default |
| `--format json` | Full `gruff.analysis.v1` payload |
| `--format html` | Self-contained dark HTML report |
| `--format markdown` | Pull-request or issue comment summary |
| `--format github` | GitHub Actions annotation commands |
| `--format hotspot` | `gruff.hotspot.v1` file offender JSON |
| `--format sarif` | SARIF 2.1.0 code-scanning output |
| `--fail-on error` | Exit non-zero for findings at or above the threshold |
| `--no-config` | Ignore `.gruff.yaml` and `[tool.gruff]` |
| `--include-ignored` | Walk normally ignored directories |
| `--min-severity warning` | Display only warning/error findings |
| `--include-pillar documentation` | Display only selected pillar findings |
| `--exclude-rule docs.missing-function-docstring` | Hide selected rule findings |

Additional commands:

| Command | Meaning |
|---|---|
| `gruff report --format html --output gruff.html` | Render an HTML or JSON report to a file or stdout |
| `gruff summary --format text` | Print compact per-pillar, top-rule, and top-file counts |
| `gruff list-rules --format json` | Print registered rule metadata |
| `gruff list` | List available commands |
| `gruff help analyse` | Display command help |
| `gruff completion bash` | Dump a shell completion script |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Run completed and no finding reached `--fail-on` |
| `1` | At least one finding reached `--fail-on` |
| `2` | Input, parse, or configuration diagnostic |

## Configuration

Config is optional. Precedence is:

1. `--config <path>`
2. `.gruff.yaml` in the project root
3. `[tool.gruff]` in `pyproject.toml`
4. Built-in defaults

Example `.gruff.yaml`:

```yaml
paths:
  ignore:
    - "tests/fixtures/**"

selection:
  excludeRules:
    - docs.missing-module-docstring

rules:
  size.file-length:
    thresholds:
      warning: 500
      error: 900
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

The JSON schema string is `gruff.analysis.v1`; hotspot output uses
`gruff.hotspot.v1`. Finding fingerprints are 16-character SHA-256 derivatives
kept compatible with the PHP implementation.

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

## Project Docs

- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security](SECURITY.md)
- [Support](SUPPORT.md)
- [Release checklist](docs/RELEASING.md)
- [License](LICENSE.md)
