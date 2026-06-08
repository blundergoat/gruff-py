# Explain a rule

`gruff-py list-rules` without arguments prints the full rule catalogue as a table — useful for surveying what's available. With a rule id, it switches to **explain mode**: a deep view of one rule's defaults, options, escape hatches, and related rules.

```bash
gruff-py list-rules naming.short-variable
```

```
Rule: naming.short-variable
  Name:      Short variable name
  Pillar:    naming
  Tier:      v0.1
  Severity:  advisory (default)
  Confidence: low
  Enabled by default: yes

Rationale:
  `naming.short-variable` protects the naming pillar by flagging short variable name
  before it becomes costly to review, maintain, or trust.

Fix guidance:
  Address the reported short variable name directly, or tune this rule with an
  explicit project configuration override when the project has a documented exception.

Default options:
  acceptedShortNames  list  Single-character identifiers accepted as conventional
                            (loop counters, math axes, exception variables).

Escape hatches:
  rules.naming.short-variable.options.acceptedShortNames  override one named option default
  rules.naming.short-variable.enabled                     set false to disable this rule entirely

Confidence:
  Low confidence: the rule is intentionally conservative and may need tuning.

Common false-positive shapes:
  (none documented yet)

Related rules:
  naming.abbreviation
  naming.identifier-quality
```

## Sections

Every detail view starts with a fixed header (id, name, pillar, tier, severity, confidence, enabled). After the header, sections appear when the rule has data to show:

- **Rationale, Fix guidance, Bad example, Good example** — sourced from the curated `RuleDocs` metadata. Most rules carry auto-generated text; a handful (e.g. `docs.dataclass-attributes`, `docs.complex-branch-rationale`) have hand-written entries.
- **Default options** — appears only when the rule has per-rule options. Each row shows the option name, type, and one-line description.
- **Escape hatches** — every config key path you can set for this rule, plus `rules.<id>.enabled` to turn it off entirely.
- **Confidence** — why the rule has its configured confidence rating.
- **Common false-positive shapes** — documented false-positive patterns and mitigations. Always shown; `(none documented yet)` when empty.
- **Related rules** — siblings users tend to consult together. Always shown; `(none)` when empty.

## JSON output

`--format json` emits the same data as a structured payload:

```bash
gruff-py list-rules naming.short-variable --format json | jq '.documentation.optionDescriptions'
```

```json
{
  "acceptedShortNames": "Single-character identifiers accepted as conventional (loop counters, math axes, exception variables)."
}
```

The single-rule JSON payload has `id`, `name`, `pillar`, `tier`, `defaultSeverity`, `confidence`, `defaultEnabled`, `options`, `documentation` (full `RuleDocs`), and `relatedRules`, plus an optional `threshold` (a single value, as on `complexity.cyclomatic`) or `thresholds` (a named map, as on `test-quality.eager-test`) key — present only for rules that define one, so the `naming.short-variable` example above has neither.

## Unknown rule ids

A typo prints suggestions and exits non-zero:

```
$ gruff-py list-rules naming.short-variabel
Error: Unknown rule: naming.short-variabel
Did you mean: naming.short-variable?
$ echo $?
1
```

## When to use it

- You're triaging a finding from `gruff-py analyse` and want to understand the rule before deciding whether to fix, configure, or suppress.
- You're configuring `.gruff-py.yaml` and need the exact escape-hatch path for one rule's options.
- You want to see what other rules cover adjacent concerns (the related-rules cluster).

For the rule-by-rule triage workflow that drives multiple of these lookups in a session, see [`docs/triage.md`](triage.md).
