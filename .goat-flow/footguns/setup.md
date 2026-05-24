---
category: setup
last_reviewed: 2026-05-24
---

## Footgun: uv sync can leave editable console scripts stale or missing

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

After dependency changes, `uv sync --all-extras --dev --locked` can consider the editable
`gruff-py` package already installed while the `gruff-py` console script is missing from
`.venv/bin`. Evidence anchors: `scripts/dependency-install.sh` (search:
`--reinstall-package gruff-py`) and `scripts/dependency-update.sh` (search:
`--reinstall-package gruff-py`).

The failure mode is that `uv pip list` shows `gruff-py` installed, but
`uv run gruff-py --version` fails with `Failed to spawn: gruff-py`, breaking
`scripts/preflight-checks.sh` self-check and performance-smoke tests. Mutating dependency
syncs should reinstall the local package with `--reinstall-package gruff-py`; non-mutating
`--check` paths should not use that flag because it intentionally reports a reinstall would
be needed.

## Resolved Entries

## Footgun: Sibling gruff-go contains scratchpad Go fixtures that are not package files

**Status:** resolved | **Created:** 2026-05-19 | **Resolved:** 2026-05-24 | **Evidence:** OBSERVED

The sibling checkout at `../gruff-go` can contain `.goat-flow/scratchpad/related-projects/`
fixture trees with malformed, intentionally unformatted, or non-package `.go` files. Evidence
anchors: `../gruff-go/.goat-flow/scratchpad/related-projects/` and
`scripts/preflight-checks.sh` (search: `RUN_BUILD=1`).

Resolved for gruff-py preflight: `scripts/preflight-checks.sh` no longer runs sibling
`gruff-go` formatting, vet, test, or dogfood checks.
