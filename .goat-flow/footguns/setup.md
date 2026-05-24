---
category: setup
last_reviewed: 2026-05-24
---

## Footgun: Sibling gruff-go contains scratchpad Go fixtures that are not package files

**Status:** active | **Created:** 2026-05-19 | **Evidence:** OBSERVED

The sibling checkout at `../gruff-go` can contain `.goat-flow/scratchpad/related-projects/`
fixture trees with malformed, intentionally unformatted, or non-package `.go` files. Evidence
anchors: `../gruff-go/.goat-flow/scratchpad/related-projects/` and
`scripts/preflight-checks.sh` (search: `go list -f "$go_list_template" ./...`).

The non-obvious failure mode is that broad shell scans such as `find . -name '*.go'` fail
inside scratchpad fixtures before reaching real gruff-go checks. For non-mutating formatting
verification, collect files from `go list` package metadata and run `gofmt -l` on those files
instead of scanning the whole checkout.

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
