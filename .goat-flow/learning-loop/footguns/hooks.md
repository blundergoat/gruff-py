---
category: hooks
last_reviewed: 2026-08-11
---

## Footgun: goat-flow install appends a duplicate Stop registration on every run

**Status:** active | **Created:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Run `goat-flow hooks sync` for every tracked agent after any `goat-flow install`, and assert distinct registrations before treating the install as done.
**Trigger phase:** VERIFY
**Incident count:** 1
**Latest occurrence:** 2026-08-11

`goat-flow install` appends the `post-turn-safety` Stop registration instead of
replacing it, so each install run leaves one more byte-identical copy in the
agent hook config. `goat-flow hooks sync` writes the same registrations
idempotently and collapses the copies back to one, so sync is the repair.

Measured 2026-08-11 on goat-flow 1.15.1 while upgrading from 1.15.0. Running
`install . --agent claude|codex|antigravity|copilot` sequentially left
`.claude/settings.json` (search: `post-turn-safety.sh`) with two identical
`Stop` entries where it previously had one, and `.codex/hooks.json` (search:
`post-turn-safety.sh`) with two where it previously had none.
`hooks sync . --agent claude` collapsed claude back to a single entry. A later
`install . --agent claude --update-config-version` re-created the duplicate,
which is what proves the append happens on every install rather than only on
the version migration.

Duplicate Stop entries do not fail `goat-flow audit`, so nothing in the normal
verification trio reports them. Check the registration counts directly, or run
`hooks sync` unconditionally after install and re-read the config.

## Resolved Entries

## Footgun: goat-flow hook sync removes the project-local Codex quality hook

**Status:** resolved | **Created:** 2026-08-06 | **Resolved:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After every Codex install or hook-state mutation, run the focused registration contract before setup continues; restore the project-owned extension when the contract fails.
**Trigger phase:** VERIFY
**Incident count:** 2
**Latest occurrence:** 2026-08-08

The project registered its changed-line quality check directly in
`.codex/hooks.json` because current Codex supports a `PostToolUse` hook, while
goat-flow 1.13.1, 1.14.0, and 1.15.0 classified `gruff-code-quality` as
unsupported for Codex. Both `goat-flow hooks sync --agent codex` and the 1.15.0
Codex installer removed the entire `PostToolUse` registration while
`.goat-flow/config.yaml` kept `gruff-code-quality.enabled: true`.

The 2026-08-08 pinned 1.15.0 installer migrated the Codex deny-hook
registration and removed `PostToolUse`. The immediate contract reproduction,
`uv run pytest tests/integration/test_hook_contract.py::test_codex_registers_post_edit_quality_hook`,
failed with `KeyError: 'PostToolUse'`; after restoring the project-owned block,
the same command reported `1 passed in 0.17s`. An earlier 2026-08-06
temporary-project reproduction measured the same removal after hook sync.

Resolved by goat-flow 1.15.1, which registers `gruff-code-quality` for Codex
itself. The manual project-owned block is gone: the registration is now managed,
matches Codex's own patch tool rather than Claude's tool names, and reaches the
script through the Node git-root launcher because Codex hooks run from the
session cwd. The contract test now pins that managed shape at
`tests/integration/test_hook_contract.py` (search: `_CODEX_PATCH_TOOL_MATCHER`),
so a regression to the removal behaviour still fails the same command.
