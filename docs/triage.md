# Triage

`gruff-py analyse` produces one line per finding. On a large run that scrolls past several screens, the flat view stops being useful — you can't tell which rule is dominating the report without reading every line. `gruff-py summary --group-by=rule` is the triage view.

## Rule-grouped overview

```bash
gruff-py summary --group-by=rule tests/
```

Output shape:

```
gruff-py 0.5.0 summary
Composite: A (99.07 / 100)
Findings: 7 total · 0 error · 0 warning · 7 advisory
Path: tests/
Files: 208 discovered, 208 parsed, 27 ignored, 0 missing, 0 parse errors
Elapsed: 5.683s

Pillars
  test-quality    A  93.70 findings=4     advisory=4     warning=0     error=0
  documentation   A  95.12 findings=3     advisory=3     warning=0     error=0
  ...

Grouped by rule (showing 4 of 4):
     3  docs.missing-param-doc               advisory  medium
     2  test-quality.trivial-snapshot        advisory  medium
     1  test-quality.loop-in-test            advisory  medium
     1  test-quality.parametrize-annotation  advisory  medium
```

Columns are count, rule id, default severity, default confidence. Rows sort by count descending, then rule id ascending. `--top N` caps the number of rows (default 10).

`--group-by=rule` changes the text summary only. `summary --format json` emits the
`gruff.summary.v3` document — the analysis envelope with only its top-level `findings` array
removed — and carries no `groupedRules` or `topRules` field.

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
