# Reporting

`gruff-py analyse` renders one report per run. All formats are generated from the
same `AnalysisReport` model.

`gruff-py report` is a convenience wrapper for release artifacts. It runs the same
analyser and writes an HTML or JSON report to stdout or `--output`.

## Formats

```bash
gruff-py analyse src/ --format text
gruff-py analyse src/ --format json
gruff-py analyse src/ --format html
gruff-py analyse src/ --format markdown
gruff-py analyse src/ --format github
gruff-py analyse src/ --format hotspot
gruff-py analyse src/ --format sarif
gruff-py report src/ --format html --output gruff-report.html
```

| Format | Best for |
|---|---|
| `text` | Local terminal review |
| `json` | Automation, snapshots, cross-implementation checks |
| `html` | Human inspection in a browser |
| `markdown` | Pull request comments and release notes |
| `github` | GitHub Actions annotation commands |
| `hotspot` | File-level offender summaries |
| `sarif` | Code-scanning upload |

## Summary

Use `summary` when CI or a release script needs aggregate counts without
per-finding output:

```bash
gruff-py summary src/ --format text
gruff-py summary src/ --format json --top 5
```

The digest includes file counts, per-pillar counts, top rules, and top file
offenders.

## JSON

JSON reports use schema string `gruff-py.analysis.v1`.

The top-level shape includes:

- `schemaVersion`
- `tool`
- `run`
- `summary`
- `ignoredPaths`
- `missingPaths`
- `diagnostics`
- `findings`
- `score`

The output is stable enough for automation, but the project is still pre-1.0.
The strongest compatibility promises are schema strings and finding
fingerprints.

## HTML

HTML reports are self-contained and do not load external fonts, scripts, or
stylesheets.

```bash
gruff-py analyse src/ --format html > gruff-report.html
```

Enable browser-side finding filters:

```bash
gruff-py analyse src/ --format html --report-interactive > gruff-report.html
```

Enable editor links:

```bash
gruff-py analyse src/ --format html --report-editor-link vscode > gruff-report.html
gruff-py analyse src/ --format html --report-editor-link phpstorm > gruff-report.html
```

## GitHub Actions

For annotations:

```yaml
- name: gruff annotations
  run: gruff-py analyse src tests --format github --fail-on warning
```

For SARIF upload, generate the file first:

```bash
gruff-py analyse src tests --format sarif --fail-on none > gruff.sarif
```

Then upload with GitHub's SARIF upload action in your workflow.

SARIF output is a renderer over the native `gruff-py.analysis.v1` report model,
not a replacement for the native JSON schema. It preserves native rule ids,
finding fingerprints, severity, paths, locations, metadata, scoring, and
fail-on behaviour. Result fingerprints are emitted as
`partialFingerprints.gruffFingerprint`, and run properties include
`gruffSchemaVersion` with the native schema string plus score and grade when
available.

The SARIF driver is named `gruff-py`, uses the project version as
`semanticVersion`, and emits registry rule metadata sorted by stable rule id.
Artifact URIs are normalized for SARIF consumers by using `/` separators and
removing leading `./`.

To validate a generated file during release or renderer changes:

```bash
uvx check-jsonschema --schemafile https://json.schemastore.org/sarif-2.1.0.json gruff.sarif
```

## Display Filters

Display filters are applied after analysis and scoring:

```bash
gruff-py analyse src/ --min-severity warning
gruff-py analyse src/ --include-pillar security
gruff-py analyse src/ --exclude-rule docs.missing-function-docstring
```

They affect rendered findings and are recorded under `run.filters`. They do not
change the exit code calculation.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Run completed and no finding reached the fail threshold |
| `1` | At least one finding reached the fail threshold |
| `2` | Diagnostic such as config error, parse error, or missing path |

Use `--fail-on none` for report-only jobs.
