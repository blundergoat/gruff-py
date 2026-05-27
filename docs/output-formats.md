# Output Formats

`gruff-py analyse --format <format>` renders the same analysis data for
different consumers. The combined legacy page remains at [Reporting](reporting.md).

## Text

Use `text` for local terminal scans:

```sh
uv run gruff-py analyse src tests --format text --fail-on warning
```

## JSON

Use `json` for automation. JSON reports use `gruff-py.analysis.v1`.

```sh
uv run gruff-py analyse src tests --format json --fail-on none > gruff-py.json
```

## HTML

Use `html` for archived human review or dashboard scan output:

```sh
uv run gruff-py report src tests --format html --output gruff-py.html
```

## Markdown

Use `markdown` for pull request comments and release notes.

## GitHub

Use `github` inside GitHub Actions to emit workflow annotations.

## Hotspot

Use `hotspot` for compact score and offender analysis.

## SARIF

Use `sarif` for GitHub code scanning or other SARIF consumers:

```sh
uv run gruff-py analyse src tests --format sarif --fail-on none > gruff-py.sarif
```

## Summary

`summary` has its own compact text/JSON contract:

```sh
uv run gruff-py summary src tests --format json --top 5
```

## Exit Codes

`analyse` exits `1` when at least one finding meets `--fail-on`. Use
`--fail-on none` for report-only jobs. The default is `advisory` for
`analyse` and `none` for `report` and `dashboard`; override via the CLI
flag or via `minimumSeverity:` in `.gruff-py.yaml` (see
[Configuration → Severity Gate](configuration.md#severity-gate)).
