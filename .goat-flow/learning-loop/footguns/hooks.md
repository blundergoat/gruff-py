---
category: hooks
last_reviewed: 2026-08-08
---

## Footgun: goat-flow hook sync removes the project-local Codex quality hook

**Status:** active | **Created:** 2026-08-06 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After every Codex install or hook-state mutation, run the focused registration contract before setup continues; restore the project-owned extension when the contract fails.
**Trigger phase:** VERIFY
**Incident count:** 2
**Latest occurrence:** 2026-08-08

The project registers its changed-line quality check directly in
`.codex/hooks.json` (search: `Gruff changed-line quality check`) because current
Codex supports a `PostToolUse` `Edit|Write` hook. Goat-flow 1.13.1, 1.14.0,
1.15.0, and upstream `main` classify `gruff-code-quality` as unsupported for
Codex. Both `goat-flow hooks sync --agent codex` and the 1.15.0 Codex installer
remove the entire `PostToolUse` registration while
`.goat-flow/config.yaml` keeps `gruff-code-quality.enabled: true`.

The 2026-08-08 pinned 1.15.0 installer migrated the Codex deny-hook
registration and removed `PostToolUse`. The immediate contract reproduction,
`uv run pytest tests/integration/test_hook_contract.py::test_codex_registers_post_edit_quality_hook`,
failed with `KeyError: 'PostToolUse'`; after restoring the project-owned block,
the same command reported `1 passed in 0.17s`. The local contract lives at
`tests/integration/test_hook_contract.py` (search:
`test_codex_registers_post_edit_quality_hook`). An earlier 2026-08-06
temporary-project reproduction measured the same removal after hook sync.

Until goat-flow's registry supports this lifecycle, do not run
`goat-flow install`, `hooks sync`, `hooks enable`, or `hooks disable` for
Codex without restoring `.codex/hooks.json` and rerunning the contract test.
Treat `.codex/hooks.json` as the project authority for this manual extension;
do not patch generated code under `node_modules/@blundergoat/goat-flow/`
because reinstalling replaces that untracked change.
