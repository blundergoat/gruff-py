# gruff-py

`gruff-py` is the Python implementation of **gruff**, an opinionated quality analyser built to **govern AI-generated code so a human can review and trust it**. It walks Python projects, scores findings across quality pillars, and emits reports for terminals, CI annotations, SARIF consumers, static HTML, and a local dashboard.

## Mission

gruff-py exists to govern **AI-generated code so a human reviewer can sign off on it**. The premise: a coding agent wrote the change, and a person who did *not* write it has to read, review, and trust it. Every rule, severity, and score is tuned for that reviewer's confidence rather than for abstract style. Wired in as a coding-agent hook, gruff-py **guides** the agent through advisory findings and **forces** it through `--fail-on`-gated warning and error findings toward code that is:

- **Legible enough to verify** — a reviewer can follow the control flow and confirm it does what was asked, without holding the whole function in their head.
- **Secure where the eye fails** — it flags the dangerous patterns and leaked secrets human review is worst at catching, because those are the failures the eye skips.
- **Tested for real, not padded** — it rewards tests that exercise behaviour and flags low-signal ceremony (assertion-free tests, tautologies, mock-only theatre) that inflates coverage without earning trust.

**Why doc comments are mandatory, even on a private one-liner:** coding agents routinely produce code that superficially works while misunderstanding the requirement. Forcing the agent to state intent, usage, contract, and failure behaviour in prose gives the reviewer something to check the implementation against — and a mismatch between the doc comment and the code is itself a signal that the change needs a deeper look.

gruff-py is heuristic static analysis: it complements `ruff`, `mypy`, `pytest`, security scanners, and human review — it does not replace them.

See [docs/mission.md](docs/mission.md) for the full statement.

## Status At A Glance

| Field | Value |
| --- | --- |
| Release line | Published `0.3.1` package line |
| Runtime | Python `3.11+` |
| Package | `gruff-py` |
| Import package | `gruffpy` with `py.typed` |
| Binary | `gruff-py` |
| Rule catalogue | 125 rules across 11 pillars |
| Primary config | `.gruff-py.yaml`; `[tool.gruff-py]` in `pyproject.toml` is also supported |
| Analysis schema | `gruff.analysis.v2` |
| Baseline schema | `gruff-py.baseline.v1`; legacy `gruff.baseline.v1` can be read |
| Severity gate | `--fail-on` with `none`, `advisory`, `warning`, `error`; project default via `minimumSeverity:` in `.gruff-py.yaml` / `pyproject.toml` |
| Dashboard | `127.0.0.1:8765` by default |

Finding fingerprints are 16-character SHA-256 derivatives kept compatible with the PHP implementation where the rule identity and finding identity match. Analysis JSON uses the shared `gruff.analysis.v2` schema string; baseline, hotspot, and config schemas remain language-prefixed. Each JSON finding also exposes a `stableIdentity` field — a line-insensitive companion to `fingerprint` for external diff tooling that needs to match "the same logical finding across line shifts" without re-baselining a moved violation; see [`docs/reporting.md`](docs/reporting.md#json) for the input set.

## Requirements

- Python `3.11+`.
- `uv` for source-checkout development.
- Git only for diff and branch-review modes.
- Optional external mutation tooling only when mutation flags are explicitly used.

## Install

Install as a project dev dependency:

```bash
uv add --dev gruff-py
uv run gruff-py init
uv run gruff-py summary
```

From a source checkout:

```bash
uv sync
uv run gruff-py --help
./bin/gruff-py --help
```

## Quick Start

```bash
# Create the project config.
uv run gruff-py init

# Review the current finding mix.
uv run gruff-py summary

# Explore without failing because of findings.
uv run gruff-py analyse src/ --fail-on none

# Gate on warning and error findings.
uv run gruff-py analyse src/ --fail-on warning

# Emit SARIF for code scanning.
uv run gruff-py analyse src/ --format sarif --fail-on none > gruff.sarif

# Generate a fresh-start baseline.
uv run gruff-py analyse src/ --generate-baseline-path gruff-baseline.json --fail-on none

# Start the local dashboard.
uv run gruff-py dashboard src/ --report-interactive
```

Open `http://127.0.0.1:8765/` for the dashboard.

## Commands

| Command | Purpose |
| --- | --- |
| `init` | Write a default `.gruff-py.yaml` to the current directory. |
| `analyse [paths...]` | Run the analyser and print findings. |
| `summary [paths...]` | Print compact score, pillar, rule, and file summaries. |
| `report [paths...]` | Render an HTML or JSON report to stdout or `--output`. |
| `list-rules [rule-id]` | Print rule metadata as text or JSON; pass a rule id for explain mode. |
| `check-ignore [paths...]` | Report whether each path is ignored, and why (exit codes mirror `git check-ignore`). |
| `dashboard [paths...]` | Serve the local browser dashboard. |
| `completion [shell]` | Print a shell completion script. |
| `list`, `help` | Show command lists and command-specific help. |

Global options mirror the broader gruff CLI surface: `--silent`, `--quiet`, `--version`, `--ansi` / `--no-ansi`, `--no-interaction`, and `--verbose`.

## Output Formats

`analyse --format <fmt>` accepts:

| Format | Use it for |
| --- | --- |
| `text` | Human terminal output. |
| `json` | Full `gruff.analysis.v2` report. |
| `html` | Self-contained inspection report. |
| `markdown` | Pull-request or issue comment summary. |
| `github` | GitHub Actions workflow annotations. |
| `hotspot` | `gruff-py.hotspot.v1` file-offender JSON. |
| `sarif` | SARIF 2.1.0 for code scanning. |

`report --format <fmt>` accepts `html` and `json`.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Run completed and no finding met `--fail-on`. |
| `1` | At least one finding met `--fail-on`. |
| `2` | Fatal diagnostic such as input, parse, configuration, baseline, or diff failure. |

`analyse` defaults to `--fail-on advisory`. Set
`minimumSeverity.analyse` in `.gruff-py.yaml` to change the default
per-project (see [docs/configuration.md](docs/configuration.md#severity-gate)).

## CI Usage

Generic CI command:

```bash
uv run gruff-py analyse src tests --format github --fail-on warning
```

SARIF jobs can write an artifact for code scanning:

```bash
uv run gruff-py analyse src tests --format sarif --fail-on none > gruff-py.sarif
```

Use `--no-baseline` for security-focused gates where adoption baselines should not hide new error-severity findings.

## Configuration

Config is optional. Precedence is:

1. `--config <path>`
2. `.gruff-py.yaml` in the project root
3. `[tool.gruff-py]` in `pyproject.toml`
4. Built-in defaults

Example `.gruff-py.yaml`:

```yaml
schemaVersion: gruff-py.config.v0.1

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

See [Configuration](docs/configuration.md) for the full shape.

## Rules And Pillars

The v0.3.1 catalogue contains 125 rules across 11 pillars:

| Pillar | Rules |
| --- | ---: |
| `size` | 7 |
| `complexity` | 4 |
| `maintainability` | 1 |
| `dead-code` | 10 |
| `modernisation` | 1 |
| `naming` | 9 |
| `documentation` | 13 |
| `security` | 34 |
| `sensitive-data` | 11 |
| `test-quality` | 34 |
| `design` | 1 |

`coupling`, `architecture`, and `mutation` are reserved schema or future catalogue names; they do not have shipping rules in `0.3.1`. See [Rules](docs/rules.md) for rule IDs, defaults, and remediation guidance.

## Baselines And Changed-Code Scans

Baselines suppress reviewed findings by fingerprint:

```bash
uv run gruff-py analyse src/ --generate-baseline-path gruff-baseline.json --fail-on none
uv run gruff-py analyse src/ --baseline-path gruff-baseline.json --fail-on warning
uv run gruff-py analyse src/ --no-baseline --fail-on none
```

Changed-code scans are changed-region aware: a finding is kept when its location
or enclosing function/class overlaps the changed hunk. JSON output includes
`suppressedCount` for findings excluded as out of scope.

```bash
uv run gruff-py analyse --format json --changed-ranges "3-3,8-10" src/foo.py
uv run gruff-py analyse --format json --since HEAD src/foo.py
git diff | uv run gruff-py analyse --format json --diff - src/foo.py
```

Display filters such as `--min-severity`, `--include-pillar`, and `--exclude-rule` reduce rendered output without changing which rules execute.

## Dashboard

```bash
uv run gruff-py dashboard src/ --host 127.0.0.1 --port 8765 --report-interactive
```

The dashboard serves a local browser UI for repeated scans. It has no authentication and is intended for local development; keep it on loopback unless the network is trusted. See [Dashboard](docs/dashboard.md) for supported controls and safety notes.

In polyglot repositories, remember that `gruff-go`, `gruff-php`, and `gruff-py` all default to port `8765`; use `--port` when running multiple dashboards at the same time.

## Trust Boundary

Default scans are local source inspections. `gruff-py` parses Python source and selected project metadata; it does not execute target application code, run tests, query vulnerability feeds, or contact package registries. Git is used only for explicit diff modes. External mutation tooling is used only when explicitly requested by mutation flags. Sensitive-data previews are redacted before they reach terminal, JSON, SARIF, GitHub, Markdown, hotspot, or HTML output.

## Stability Contract

The `0.1.x` line treats rule IDs, finding fingerprints, baseline identity, `gruff.analysis.v2`, `gruff-py.baseline.v1`, `gruff-py.hotspot.v1`, SARIF rendering, and CLI exit semantics as compatibility-sensitive. Breaking changes should be tagged as a future minor release and recorded in [`CHANGELOG.md`](CHANGELOG.md).

## How It Compares

| Tool | Relationship |
| --- | --- |
| `ruff` | Fast linting and formatting. `gruff-py` adds scoring, baselines, reports, dashboard, and project-quality rules. |
| `mypy` / Pyright | Type checking. `gruff-py` does not prove type correctness. |
| `pytest` | Runtime tests. `gruff-py` can flag test-quality smells but does not prove behavior. |
| Bandit / Semgrep / vulnerability scanners | Security-focused checks. `gruff-py` reports local static signals and does not replace specialized scanners. |
| Vulture / dead-code tools | Focused unused-code detection. `gruff-py` includes broader quality scoring and reporting. |

## Development

```bash
uv sync --extra dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest
make check
```

`make check` uses the `lint` target, which runs `ruff check --fix`. Use the explicit commands above when you need non-mutating release verification.

## Documentation

- [Mission](docs/mission.md)
- [Changelog](CHANGELOG.md)
- [Configuration](docs/configuration.md)
- [Rules](docs/rules.md)
- [Reports](docs/reporting.md)
- [Dashboard](docs/dashboard.md)
- [Release checklist](docs/releasing.md)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security](SECURITY.md)
- [Support](SUPPORT.md)

## Author

Built by [Matthew Hansen](https://www.blundergoat.com/about).

## License

[MIT](LICENSE.md)
