---
category: hooks
last_reviewed: 2026-08-06
---

## Footgun: goat-flow hook sync removes the project-local Codex quality hook

**Status:** active | **Created:** 2026-08-06 | **Evidence:** OBSERVED

The project registers its changed-line quality check directly in
`.codex/hooks.json` (search: `Gruff changed-line quality check`) because current
Codex supports a `PostToolUse` `Edit|Write` hook. Goat-flow 1.13.1, 1.14.0, and
upstream `main` still classify `gruff-code-quality` as unsupported for Codex.
Running `goat-flow hooks sync --agent codex` therefore removes the entire
`PostToolUse` registration even while `.goat-flow/config.yaml` keeps
`gruff-code-quality.enabled: true`.

This was reproduced on 2026-08-06 in a temporary project copied from the
tracked hook files: before sync, `.codex/hooks.json` contained `PostToolUse` and
`gruff-code-quality.sh`; after sync, neither string remained. The upstream
registry reason was `Codex goat-flow hooks are PreToolUse-only until a
supported post-tool lifecycle path is verified.` The local contract test at
`tests/integration/test_hook_contract.py` (search:
`test_codex_registers_post_edit_quality_hook`) detects the resulting drift.

Until goat-flow's registry supports this lifecycle, do not run
`goat-flow hooks sync`, `hooks enable`, or `hooks disable` for Codex without
restoring `.codex/hooks.json` and rerunning the contract test. Treat
`.codex/hooks.json` as the project authority for this manual extension; do not
patch the generated code under `node_modules/@blundergoat/goat-flow/` because
that change is untracked and disappears on reinstall.
