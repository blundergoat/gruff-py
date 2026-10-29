# Contributing

Thanks for taking the time to improve gruff-py.

## Development Setup

```bash
uv sync --extra dev
uv run gruff-py --help
```

## Checks

Run the non-mutating verification gate before opening a pull request:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest
```

`make check` is convenient during development, but it runs `ruff check --fix`
through the `lint` target. Use the explicit commands above when preparing a
review or release.

## Rule Changes

When adding or changing a rule:

- Keep rule IDs stable once released.
- Add focused unit tests under `tests/unit/rule/<pillar>/`.
- Add or update integration tests when CLI behaviour changes.
- Include severity, confidence, thresholds, and default-enabled status in the
  rule definition.
- Avoid overlapping with tools that already own style-only checks. For example,
  ruff owns PEP 8 naming case style; gruff-py owns naming intent.

## Compatibility Boundaries

Be careful with:

- `gruff.analysis.v3`
- `gruff.summary.v3`
- `gruff.baseline.v3`
- `gruff-py.hotspot.v1`
- finding fingerprint inputs
- rule IDs
- score weights and grade bands
- report format names

Changes in those areas should be intentional and called out in the changelog.

The schema-string prefixes are deliberately mixed: analysis, summary, and
baseline use the language-neutral `gruff.*` family (e.g. `gruff.analysis.v3`) so
cross-port consumers share one string, while hotspot and config stay
language-prefixed (`gruff-py.*`). Do not "unify" the remaining language-prefixed
strings to finish an apparent migration — that split is intentional, and any
change must be coordinated across the sibling implementations. A
`gruff-py.baseline.v1` or `gruff.baseline.v1` file is a legacy input that fails
closed, not a current output.

## Commit Style

Use focused commits. Conventional commit prefixes are welcome:

```text
feat: add markdown reporter
fix: preserve fingerprint compatibility
docs: document dashboard controls
test: cover config precedence
```

