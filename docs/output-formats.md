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

Use `json` for automation. Analysis reports use `gruff.analysis.v3`:

```sh
uv run gruff-py analyse src tests --format json --fail-on none > gruff-py.json
```

Version 3 is the coordinated family machine contract. Paths are
project-relative POSIX paths, `run.projectRoot` is `.`, and unavailable
optional fields are omitted rather than emitted as `null`. The shared
top-level sections are `schemaVersion`, `tool`, `run`, `summary`,
`score`, `diagnostics`, `findings`, `paths`, and `suppressions`.
`baseline`, `diff`, `displayFilter`, and `extensions` appear only when
their feature is active.

### Migrating v2 consumers

Version 3 is a hard break with no v2 writer or compatibility flag:

| v2 | v3 |
|---|---|
| top-level `ignoredPaths`, `ignoredPathDetails`, and `missingPaths` | `paths.ignoredPaths`, `paths.details`, and `paths.missingPaths` |
| nullable `column`, `endLine`, or `symbol` | omit the unavailable key |
| flat or separately graded composite | `score.composite.{score,grade}` |
| `score.topOffenders[].filePath` | `score.topOffenders[].file` |
| `run.partialContextCaveat` | `run.extensions.py.run.partialContextCaveat` |
| top-level `suppressedCount` and `diff.suppressedCount` | `summary.suppressedFindings` and `diff.filteredFindings` |
| top-level Python mutation, review, or trend data | `extensions.py.topLevel.{mutation,review,trend}` |
| independent compact summary fields | the `gruff.summary.v3` analysis projection |

The v3 machine adapter preserves every native fingerprint, `stableIdentity`,
score, grade, baseline result, and exit-code decision.

### Finding identity

Every finding carries one `file` path and two identity fields:

- `fingerprint` — the line-precise 16-character SHA-256 prefix. Neither
  baselines nor SARIF read it any more; both use the line-free baseline
  identity.
- `stableIdentity` — the line-insensitive 16-character SHA-256 prefix for
  external diff tooling.

`column`, `endLine`, and `symbol` appear only when known.
`metadata.locationPrecision` is `scanner-pinpointed` when a column is known
and `line-only` otherwise. The envelope changes no identity input or matching
behavior.

### Paths, run context, and suppressions

`paths.details` records each excluded path with `path`, canonical `reason`,
`source`, and `pattern` when a pattern caused the skip.
`paths.ignoredPaths` is the exact ordered path projection of those details.

When a requested path is narrower than the project root and a project-wide rule
is active, machine JSON records the existing caveat at
`run.extensions.py.run.partialContextCaveat`. Human reports continue to label
it as scan context. Native `score.scope` and hotspot `scope` remain scoring
mode, not discovery coverage.

Every analysis and summary document includes `suppressions`, with one
`{index, rule, paths, symbol?, reason, suppressed}` row per configured
`sensitiveExclusions` entry, including entries that matched nothing. The array
is empty when no exclusion is configured. See
[Sensitive Data Exclusions](configuration.md#sensitive-data-exclusions).

## Changed-Region Scoping (native diff mode)

`analyse` can scope a run to just-changed code so an agent hook surfaces only the
findings tied to the lines it edited, instead of pre-existing debt elsewhere in the
same file. All five ports now share the v3 changed-region accounting locations
described below.

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

In changed-region mode, every finding collected by the unfiltered run is either
surfaced or counted as removed by region filtering. The count is published at
both `summary.suppressedFindings` and `diff.filteredFindings`; the values are
equal. With no display filter,
`len(findings) + summary.suppressedFindings` equals the full-file finding
count.

Display filters apply after analysis and region filtering. They can reduce
`findings[]`, while `summary.findings`, `score`, and
`summary.exitCode` continue to describe the full analysed set;
`displayFilter.hiddenFindings` records the display-only difference.

The `diff` section also carries `enabled`, mode, changed files, and any
changed-region caveat. A full scan omits `diff`,
`summary.suppressedFindings`, and `diff.filteredFindings`.

CI workflows that still want whole-file aggregate findings for pull-request
diffs should run a full scan or a companion hunk-scope scan. Full scans emit all
file-wide findings; hunk scope keeps findings whose reported span intersects the
changed lines.

Findings use the normative flat shape with one `file` key and optional
location and symbol keys omitted when unavailable. Ignore evidence lives under
`paths`: `paths.ignoredPaths` is the string projection of
`paths.details`, and `paths.missingPaths` lists unresolved requested paths.
All five ports now share these v3 locations.

## Hook JSON

`gruff-py hook --format json` emits the separate agent-hook contract rather
than the native `gruff.analysis.v3` report:

```json
{
  "contractVersion": "gruff.hook.v2",
  "analyzer": { "name": "gruff-py", "version": "0.5.0" },
  "run": {
    "mode": "full",
    "scope": "file",
    "paths": ["src"],
    "analysedFiles": 1,
    "baseline": { "applied": false, "schemaVersion": null, "path": null }
  },
  "findings": [],
  "suppressed": { "count": 0 },
  "suppressions": [
    {
      "rule": "sensitive-data.aws-access-key",
      "path": "tests/fixtures/aws-sample.env",
      "symbol": null,
      "reason": "Synthetic key used by the loader fixture; not a live credential.",
      "suppressed": 0
    }
  ],
  "ignored": { "paths": [] },
  "diagnostics": [],
  "config": { "schemaOk": true, "error": null }
}
```

The hook `suppressions` row is not the analysis row. `analyse` and `summary`
publish `index`, `rule`, `paths` as an array, `reason`, `suppressed`, and
`symbol` only on an entry that scopes itself to one (see
[Configuration → Sensitive Data Exclusions](configuration.md#sensitive-data-exclusions)).
The hook row carries `rule`, a single `path` string, `symbol` — always present,
`null` when the entry names no symbol — `reason`, and `suppressed`. It has no
`index`; rows follow configuration order. `suppressed` is `0` for an entry that
matched nothing in this run, so a row means the exclusion is configured, not
that it silenced anything.

Hook findings use the contract's normative names: `file`, `scope`, non-null
`remediation`, `stableIdentity`, optional `fingerprint`, and threshold metadata
with `measured`, `threshold`, `unit`, and `direction`. `hook` exits `0` after a
successful analysis even when findings are present, because its own `--fail-on`
defaults to `none`; `--fail-on <severity>`, `--fail-on-new`, and
`--fail-on-diagnostics` are the explicit consumer requests that exit `1`
instead. Operational failures such as invalid config exit `2` and still render a
hook JSON payload when config loading is the failure.

`gruff-py hook --capabilities --format json` advertises the same
`gruff.hook.v2` contract, supported flags, and `flagOrder`.

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

HTML metadata labels `full-project` or `diff` as scoring mode and adds a
separate escaped scan-context section only when the run carries
`run.extensions.py.run.partialContextCaveat`.

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

SARIF is a renderer over the native `gruff.analysis.v3` model, not a
replacement schema. It preserves native rule ids, fingerprints, severity,
paths, locations, metadata, scoring, and fail-on behavior. The durable baseline
identity is emitted as `partialFingerprints.gruffFingerprint`; a sensitive
finding carries no `partialFingerprints` object at all, so no secret is given a
durable name in code scanning. Run properties carry
`gruffSchemaVersion` with the native v3 schema plus score and grade when
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

`summary --format json` emits the exact findings-free projection of the
corresponding analysis document. Only the top-level `findings` array is
removed and the schema changes to `gruff.summary.v3`:

```sh
uv run gruff-py summary src tests --format json --top 5
```

Counts, scores, diagnostics, paths, suppressions, baseline, diff, and extensions
therefore keep their analysis values. `--top` and `--group-by` affect text
summary only.

To read a noisy run rule-by-rule, see [Triage](triage.md).

## Rule And Pillar Selection

`--exclude-rule`, `--include-rule`, `--exclude-pillar`, and `--include-pillar`
are execution-level: the excluded rules do not run, so the score and the exit
code move with them.

```sh
uv run gruff-py analyse src/ --exclude-rule docs.missing-function-docstring
uv run gruff-py analyse src/ --include-pillar security
```

Because the rules never ran, these selectors leave no `run.filters` entry and no
`displayFilter` block. `summary.findings` and `score.composite` describe the
narrowed run, and a baseline generated under them records only the rules that
ran. They are the one-run form of config `selection` (see
[Configuration → Display Filters Are Not Config Selection](configuration.md#display-filters-are-not-config-selection)).

## Display Filters

Display filters apply after analysis and scoring. They are `--min-severity`,
`--hide-rule`, `--show-rule`, `--hide-pillar`, and `--show-pillar`:

```sh
uv run gruff-py analyse src/ --min-severity warning
uv run gruff-py analyse src/ --show-pillar security
uv run gruff-py analyse src/ --hide-rule docs.missing-function-docstring
```

Display filters change only which findings are rendered and are recorded under
`run.filters`. They do not change analysis, score, or exit-code calculation.
Text reports disclose the hidden count; JSON keeps full-run counts in
`summary.findings` and reports the presentation delta in
`displayFilter.hiddenFindings`.

## Exit Codes

`analyse` exits `1` when at least one finding meets `--fail-on`. Use
`--fail-on none` for report-only jobs. `--fail-on` gates findings only. Parse
errors are fatal diagnostics and exit `2` even with `--fail-on none`, so
`none` makes findings report-only rather than making every diagnostic
successful. The default is `advisory` for `analyse` and `none` for `report`
and `dashboard`; override via the CLI flag or via `failOn:` in
`.gruff-py.yaml` (see
[Configuration → Severity Gate](configuration.md#severity-gate)).
