---
category: setup
last_reviewed: 2026-05-25
---

## Footgun: deleting a rule `.py` file leaves stale `__pycache__/*.pyc` that may keep the rule "registered"

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

hallucination-risk: high (the change you made to `catalog.py` looks correct, the test suite passes for the deleted-rule path, and yet a freshly-run `gruff-py init` keeps emitting the deleted rule's block — easy to misdiagnose as "my edit didn't take" and re-edit unrelated files)

Evidence:
- Measured 2026-05-25 while removing `naming.parameter-type-name` (see [ADR-018](../decisions/ADR-018-retire-naming-parameter-type-name.md)):
  1. Deleted `src/gruffpy/rule/naming/parameter_type_name_rule.py`.
  2. Edited `src/gruffpy/rule/catalog.py` to remove the import and the `_entry(ParameterTypeNameRule)` registration line. `grep parameter_type_name_rule src/gruffpy/rule/catalog.py` returned zero matches.
  3. Ran `gruff-py init` in a clean `/tmp` scratch dir. The rendered `.gruff-py.yaml` still contained `naming.parameter-type-name:` with the full options block.
  4. `find … -name "parameter_type_name*"` returned exactly one survivor: `src/gruffpy/rule/naming/__pycache__/parameter_type_name_rule.cpython-312.pyc` (size 22243, dated 10:25). The sibling `catalog.cpython-312.pyc` was also stale.
  5. `find … -name "__pycache__" -not -path "*/.venv/*" | xargs rm -rf` followed by another `gruff-py init` produced a clean YAML with zero references to the deleted rule.
- `.venv/lib/python3.12/site-packages/_editable_impl_gruff_py.pth` (search: `gruff-py/src`) — the editable-install `.pth` injects the project's `src/` directly into `sys.path`, so the loaded modules are the ones whose source you just edited, but they share the *same `__pycache__` directory* with the in-tree cached bytecode. A stale `.pyc` here is *not* a separate venv install; it's the cache the loader will reach for next.

How to avoid:
- After deleting any `src/gruffpy/**/*.py`, clear cached bytecode before re-running any tool that exercises the import graph (`gruff-py`, `uv run pytest`, `uv run python -m gruffpy.command.rule_docs`, etc.):
  ```bash
  find src -name "__pycache__" -type d | xargs rm -rf
  find tests -name "__pycache__" -type d | xargs rm -rf
  ```
- Do not rely on `mtime`-based bytecode invalidation. Mtime checks compare the source's mtime to the `.pyc`'s recorded mtime; when the source is *gone* the comparison is skipped, and the resulting orphan-`.pyc` handling depends on the loader registered for the parent package — which for editable installs has historically surprised at least one observer (this one).
- If `gruff-py init` or `uv run pytest` still appears to reference a rule whose `.py` you deleted, the first hypothesis is "stale `__pycache__`" — verify with `find src -path '*__pycache__*' -name '<deleted_module>*'` before re-investigating `catalog.py` or the registry.

This trap does not exist in `gruff-php` (PHP has no on-disk bytecode cache by default; OPcache is in-memory and process-bounded).

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
