---
category: setup
last_reviewed: 2026-05-19
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
