# ADR-015: Dead-code allowlist config shape

**Status:** Accepted
**Date:** 2026-05-18
**Ticket/Context:** M18 dead-code reachability and allowlists; coordinated with
ADR-006 (cross-impl config shape) and ADR-008 (rule suppression syntax).

## Decision

Add a top-level `allowlists.deadCode` config section that excludes specific
symbols, decorators, or file paths from a narrow opt-in set of dead-code rules:

```yaml
allowlists:
  deadCode:
    symbols:
      - "MyService._on_event_consumed_by_framework"
      - "plugins:_register"
    decorators:
      - "register_event"
      - "click.command"
    paths:
      - "tests/fixtures/**/*.py"
      - "src/legacy/**"
```

Applies to:

- `dead-code.unused-private-function`
- `dead-code.unused-private-attribute`

Other dead-code and waste rules (unreachable-code, unused-import,
unused-parameter, commented-out-code, empty-class, empty-function,
one-line-function, redundant-variable) are **not** affected; their existing
dynamism safeguards are sufficient or out of scope for v0.1.

Each allowlist axis is a list of strings:

- `symbols` - exact qualified names (e.g. `ClassName.method_name`).
  Match is exact-string against the rule's `symbol` finding field. No globbing.
- `decorators` - decorator names. Match is exact-string against the rightmost
  attribute of the decorator expression (`@register_event`, `@app.route` matches
  `app.route`, `@functools.wraps(x)` matches `functools.wraps`).
- `paths` - glob patterns evaluated with `fnmatch.fnmatchcase` against the
  finding's `file_path` (display path, forward slashes). `**` matches any
  path segments.

Defaults: every axis is empty. Empty/missing `allowlists.deadCode` is the
zero-cost default.

## Context

M13 dogfood and related-project review surfaced that Python dead-code rules
need an escape hatch for framework-injected references (Flask routes, pytest
fixtures, Click commands, plugin entry points) and fixture trees that look
unused but are loaded dynamically.

Existing mechanisms:

- `paths.ignore` filters source discovery - too coarse: it removes the file
  from analysis entirely, losing other-rule findings.
- Suppression comments (ADR-008) - local but require touching every callsite,
  which is exactly the wrong direction when the framework adds the implicit
  reference.
- `_python_dynamism` heuristic safeguards inside rules - already catches
  `__all__`, `getattr`, decorator-injection patterns; allowlist is for the
  cases the heuristic can't infer.

## Contract

- `allowlists.deadCode` is a table.
- Sub-keys: `symbols`, `decorators`, `paths`. Each is a list of strings.
- Unknown sub-keys are rejected by the loader.
- Non-list or non-string values are rejected.
- Applies only to the two private dead-code rules listed above.
- Precedence (most-specific wins):
  1. `paths.ignore` source-discovery filter (file never analyzed).
  2. `# gruff: disable=...` suppression comments (per-line / per-file).
  3. `allowlists.deadCode` (per-rule, narrow opt-in).
  4. Built-in dynamism heuristics (`_python_dynamism`).
- Allowlist filtering happens **after** the rule emits findings, before
  baseline matching and scoring.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Top-level `allowlists.deadCode` with three axes | Adds a new public config surface that must stay stable across implementations. | Accepted: matches the existing `allowlists` pattern, separates dead-code policy from `paths.ignore`, and keeps suppression comments as the most local override. |
| Per-rule `options.allowlist` | Duplicates the list when multiple rules share an allowlist; muddles the rule-options surface (which today is for tuning knobs, not finding filters). | Rejected: ergonomic regression for the common case, and rule-options shape is reserved for behavior tuning per the existing convention. |
| Reuse `paths.ignore` for path-based dead-code exemptions | Removes the file from analysis entirely. Loses size, complexity, security findings. | Rejected: paths.ignore is a discovery filter, not a per-rule filter. |
| Suppression comments only | Requires touching every callsite the framework injects, which is the case the allowlist is supposed to fix. | Rejected: doesn't solve the framework-injection problem. |
| Apply allowlist to all dead-code + waste rules | Broader surface and easier to mis-suppress legitimate findings; diverges from PHP without a sibling change. | Rejected for v0.1: stay narrow until cross-impl coordination lands. |

## Consequences

- `AnalysisConfig` grows a `dead_code_allowlist: DeadCodeAllowlist` field.
- `DeadCodeAllowlist` is a frozen value object with three tuple fields.
- `_apply_allowlists` in the loader gains a `deadCode` sub-key handler.
- The two private dead-code rules check the allowlist after emitting candidate
  findings.
- Documentation: `.gruff-py.yaml` example block and rule-catalog notes for the
  two affected rules.
- gruff-php parity: this is a gruff-py-local addition for v0.1. The cross-impl
  contract memory does not pin `allowlists.deadCode` yet. Cross-impl
  coordination is deferred to a v0.2 milestone.

## Reversibility

Reversible in a single release: drop the loader handler, remove the
`AnalysisConfig` field, and remove the rule checks. No fingerprint, schema
key, or scoring change.

Revisit triggers:

- gruff-php adds a different allowlist shape; the cross-impl contract must
  reconcile.
- New dead-code rules need allowlist support; the opt-in list grows.
- Glob behavior on `symbols` is requested (currently exact-match only); a
  named option such as `symbolPatterns` would be added alongside.
