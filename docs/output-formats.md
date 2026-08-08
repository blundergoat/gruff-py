# Output Formats

`gruff-py analyse --format <format>` renders the same analysis data for
different consumers. Every format is generated from one `AnalysisReport` model,
so switching format changes presentation, never which findings were produced.

`gruff-py report` is a convenience wrapper for release artifacts: it runs the
same analyser and writes HTML or JSON to stdout or `--output`.

This page is the reference for every format. [Reporting](reporting.md) is kept
as a stable link target and points back here.

## Text

Use `text` for local terminal scans:

```sh
uv run gruff-py analyse src tests --format text --fail-on warning
```

## JSON

Use `json` for automation. JSON reports use `gruff.analysis.v2`.

```sh
uv run gruff-py analyse src tests --format json --fail-on none > gruff-py.json
```

The top-level shape is `schemaVersion`, `tool`, `run`, `summary`,
`ignoredPaths`, `ignoredPathDetails`, `missingPaths`, `diagnostics`, `findings`,
and `score`. Changed-region runs add `suppressedCount` and `diff`; a full scan
emits neither. The output is stable enough for automation, but the project is
pre-1.0 — the strongest compatibility promises are the schema strings and the
finding identity fields below.

### Finding identity

Every finding payload exposes two identity fields:

- `fingerprint` — line-precise 16-character SHA-256 prefix derived from
  `[ruleId, file, line, endLine, column, symbol]`. Baseline matching
  (`BaselineFilter` and `gruff-baseline.json`) and SARIF
  `partialFingerprints.gruffFingerprint` consume this one.
- `stableIdentity` — line-insensitive 16-character SHA-256 prefix derived from
  `[ruleId, file, symbol]`, falling back to `[ruleId, file, message]` when
  `symbol` is `null`. Use it for external diff tooling that needs to match the
  same logical finding across line shifts without re-baselining a moved
  violation.

Both digests use the same PHP-compatible canonical-JSON encoding, so cross-port
consumers see identical values for identical inputs.

When a requested path is narrower than the project root and at least one
project-wide rule is enabled, JSON additively records
`run.partialContextCaveat`. Text, Markdown, and HTML present the same caveat as
**scan context**. Changed-region scans (`--diff`, `--since`) classify as partial
the same way because discovery narrows to changed files. When the caveat is
absent, human reports do not infer or display a full scan-context claim because
no project-wide rule may have required one.

Native `score.scope` and hotspot `scope` remain the existing **scoring mode**:
`full-project` for normal scoring or `diff` when changed-region filtering shapes
the score. They do not describe discovery coverage. The caveat and labels do
not change findings, scores, fingerprints, filters, or exit codes, and no
`scanScope` field is emitted.

## Changed-Region Scoping (native diff mode)

`analyse` can scope a run to just-changed code so an agent hook surfaces only the
findings tied to the lines it edited, instead of pre-existing debt elsewhere in the
same file. gruff-py is the reference implementation for this contract; the other
gruff ports are being aligned to the shape below.

The native (delegated) invocation a hook sends:

```sh
gruff-py analyse --format json --fail-on none --no-baseline \
  --changed-ranges <ranges> --changed-scope symbol <file>
```

- `--changed-ranges <ranges>` — inclusive, comma-separated one-based line ranges
  (e.g. `12-18,40-40`). The analyzer owns the scoping; a caller using native mode
  trusts it and does **not** re-filter findings by line.
- `--changed-scope symbol` — widen each changed range to its enclosing declaration
  (function, method, or class), so editing a body still surfaces that symbol's
  signature-line findings. Whole-file and class-level aggregate findings are
  anchored under symbol scope, so inherited aggregate debt is suppressed unless
  the edit touches the finding's anchor line or header. `--changed-scope hunk`
  restricts to the literal changed lines instead.
- `--no-baseline` — do not auto-apply a baseline file, so an adoption baseline can
  not hide the agent's own feedback.

Native mode is available when `analyse --help` advertises all three flags
(`--changed-ranges`, `--changed-scope`, `--no-baseline`).

### Suppressed-count accounting

In changed-region mode every finding a full scan would produce is either
**surfaced** in `findings[]` or **suppressed** as out-of-scope. The suppressed
total is reported in two places that are always equal:

- top-level `suppressedCount`, and
- `diff.suppressedCount`.

So `len(findings) + suppressedCount` equals the full-file finding count — nothing
is dropped silently. `suppressedCount` reflects the full rule set the run collected;
display filters (`--include-rule`, `--exclude-rule`, `--min-severity`) narrow
`findings[]` only, so the native trio above — with no display filter — is where that
identity is exact. Display filters do not change score or exit-code calculation; text output
discloses hidden findings, while JSON `summary.findings` remains aligned with displayed findings.
The `diff` section also carries `enabled`, `source`,
`changedFiles`, and a `caveat` that project-wide rules may need full context. Both
the top-level `suppressedCount` and the `diff` section appear **only** when
changed-region scoping is active; a full scan emits neither.

CI workflows that still want whole-file aggregate findings for pull-request
diffs should run a full scan or a companion hunk-scope scan. Full scans emit all
file-wide findings; hunk scope keeps findings whose reported span intersects the
changed lines.

Findings keep the normative flat shape (`file`, `line`, `endLine`, `column`,
`symbol`, `severity` ∈ `advisory | warning | error`, `ruleId`, `message`,
`fingerprint`, …). Config-ignored files are reported at the top level under
`ignoredPaths` (string paths) plus `ignoredPathDetails`, in every invocation mode.

> Cross-port note: gruff-py and gruff-php expose `ignoredPaths` at the **top
> level**; gruff-rs, gruff-ts, and gruff-go nest it under `paths`. gruff-py is left
> unchanged here on purpose — the workspace contract owner tracks convergence.

## Hook JSON

`gruff-py hook --format json` emits the agent-hook contract rather than the
native `gruff.analysis.v2` report:

```json
{
  "contractVersion": "gruff.hook.v1",
  "analyzer": { "name": "gruff-py", "version": "0.5.0" },
  "findings": [],
  "suppressed": { "count": 0 },
  "ignored": { "paths": [] },
  "config": { "schemaOk": true, "error": null }
}
```

Hook findings use the contract's normative names: `file`, `scope`, non-null
`remediation`, `stableIdentity`, optional `fingerprint`, and threshold metadata
with `measured`, `threshold`, `unit`, and `direction`. `hook` exits `0` after a
successful analysis even when findings are present; operational failures such as
invalid config exit `2` and still render a hook JSON payload when config loading
is the failure.

`gruff-py hook --capabilities --format json` advertises the same
`gruff.hook.v1` contract, supported flags, and `flagOrder`.

`hook --exclude-rule <rule-id>` is execution-level and removes matching rules
from the hook payload. It accepts comma-separated and repeated values.

## HTML

Use `html` for archived human review or dashboard scan output:

```sh
uv run gruff-py report src tests --format html --output gruff-py.html
```

HTML reports are self-contained: no external fonts, scripts, or stylesheets.
Two optional renderers extend them:

```sh
uv run gruff-py analyse src/ --format html --report-interactive > gruff-py.html
uv run gruff-py analyse src/ --format html --report-editor-link vscode > gruff-py.html
```

`--report-interactive` adds browser-side finding filters; `--report-editor-link`
accepts `vscode` or `phpstorm` and turns file references into editor links.

HTML metadata labels `full-project`/`diff` as **scoring mode** and adds a
separate escaped **scan context** section only when the run carries
`run.partialContextCaveat`.

## Markdown

Use `markdown` for pull request comments and release notes.

Markdown uses the same **Scoring mode** and optional **Scan context** labels as
the terminal and HTML reports.

## GitHub

Use `github` inside GitHub Actions to emit workflow annotations.

## Hotspot

Use `hotspot` for compact score and offender analysis.

The existing hotspot `scope` key is scoring mode, not scan coverage.

## SARIF

Use `sarif` for GitHub code scanning or other SARIF consumers:

```sh
uv run gruff-py analyse src tests --format sarif --fail-on none > gruff-py.sarif
```

SARIF is a renderer over the native `gruff.analysis.v2` model, not a replacement
schema. It preserves native rule ids, fingerprints, severity, paths, locations,
metadata, scoring, and fail-on behaviour. Fingerprints are emitted as
`partialFingerprints.gruffFingerprint`, and run properties carry
`gruffSchemaVersion` with the native schema string plus score and grade when
available. The driver is named `gruff-py`, uses the project version as
`semanticVersion`, and emits registry rule metadata sorted by stable rule id.
Artifact URIs use `/` separators with leading `./` removed.

Validate a generated file when releasing or changing the renderer:

```sh
uvx check-jsonschema --schemafile https://json.schemastore.org/sarif-2.1.0.json gruff-py.sarif
```

Upload it with GitHub's SARIF upload action; see
[CI Integration](ci-integration.md#github-actions) for a working workflow.

## Summary

`summary` has its own compact text/JSON contract, covering file counts,
per-pillar counts, top rules, and top file offenders:

```sh
uv run gruff-py summary src tests --format json --top 5
```

To read a noisy run rule-by-rule, see [Triage](triage.md).

## Display Filters

Display filters apply after analysis and scoring:

```sh
uv run gruff-py analyse src/ --min-severity warning
uv run gruff-py analyse src/ --include-pillar security
uv run gruff-py analyse src/ --exclude-rule docs.missing-function-docstring
```

They change which findings are rendered and are recorded under `run.filters`.
They do not change the score or the exit code. Text output reports how many
findings were hidden; in JSON, `summary.findings` follows displayed findings
while `score` and `summary.exitCode` reflect the full analysed set.

## Exit Codes

`analyse` exits `1` when at least one finding meets `--fail-on`. Use
`--fail-on none` for report-only jobs. The default is `advisory` for
`analyse` and `none` for `report` and `dashboard`; override via the CLI
flag or via `minimumSeverity:` in `.gruff-py.yaml` (see
[Configuration → Severity Gate](configuration.md#severity-gate)).
