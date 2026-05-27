# Triage

`gruff-py analyse` produces one line per finding. On a large run that scrolls past several screens, the flat view stops being useful — you can't tell which rule is dominating the report without reading every line. `gruff-py summary --group-by=rule` is the triage view.

## Rule-grouped overview

```bash
gruff-py summary --group-by=rule src/
```

Output shape:

```
gruff 0.2.0 summary
Path: src
Files: 213 discovered, 213 parsed, 22 ignored, 0 missing, 0 parse errors
Findings: 102
Elapsed: 3.074s

Pillars
  complexity      F   0.00 findings=64    advisory=0     warning=64    error=0
  naming          F   0.00 findings=34    advisory=34    warning=0     error=0
  ...

Grouped by rule (showing 9 of 9):
    32  complexity.npath                  warning   medium
    28  naming.abbreviation               advisory  medium
    17  complexity.cyclomatic             warning   high
     8  complexity.cognitive              warning   high
     7  complexity.nesting-depth          warning   high
     6  naming.module-name-mismatch       advisory  medium
     2  complexity.maintainability-index  warning   medium
     1  docs.missing-function-docstring   warning   high
     1  size.file-length                  error     high
```

Columns are count, rule id, default severity, default confidence. Rows sort by count descending, then rule id ascending. `--top N` caps the number of rows (default 10).

JSON output additively gains a `groupedRules` field with `{shown, total, rows}`. Each row carries `ruleId`, `count`, `severity`, `confidence`. The existing `topRules` field stays unchanged for back-compat:

```bash
gruff-py summary --format json --group-by=rule src/ | jq '.groupedRules.rows[0]'
```

## Recommended workflow

1. **Triage**: `gruff-py summary --group-by=rule src/` to see which rules are dominating.
2. **Decide per rule**: for each rule that matters, choose one action — fix, configure away (per-rule threshold/options), or suppress with a focused exception.
3. **Fix one rule at a time**: `gruff-py analyse src/ --include-rule <rule-id>` narrows the flat view to just that rule's findings so you can work through them without distraction.
4. **Re-run summary**: confirm the count dropped before moving to the next rule.

## Output-volume hint

`gruff-py analyse --format text` appends a one-line hint pointing at this command when the run produces a lot of findings. The threshold defaults to 50 and is configurable via the top-level `outputVolumeHintThreshold:` key in `.gruff-py.yaml` (or `[tool.gruff-py]` in `pyproject.toml`). Set it to `0` to suppress the hint entirely:

```yaml
schemaVersion: gruff-py.config.v0.1
outputVolumeHintThreshold: 200
```

The hint is only emitted from the `text` format. JSON, HTML, Markdown, GitHub annotations, hotspot, and SARIF outputs are never altered by the hint.
