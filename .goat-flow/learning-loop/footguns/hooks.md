---
category: hooks
last_reviewed: 2026-11-23
---

## Footgun: goat-flow 1.19.0 install exits 1 for each provider still on the retired bash runtime

**Status:** active | **Created:** 2026-11-23 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** When an upgrade replaces the hook runtime, run `install . --agent <id>` for every tracked agent, then re-run it for each agent that did not print `Install verified for <agent>`; a `Runtime migration is incomplete` exit is not a reason to roll back unless the re-run also fails.
**Trigger phase:** ACT
**Incident count:** 1
**Latest occurrence:** 2026-11-23

Upgrading 1.18.0 to 1.19.0, sequential `install . --agent claude|codex|antigravity|copilot`
runs exited 1 for claude, codex, and antigravity with `Fatal error: Runtime migration is
incomplete: a provider still references the retired runtime. Its dependencies were preserved.`
Each failed run had already moved its own provider's registrations from
`run-with-bash.mjs` and the `.sh` hooks to `.goat-flow/hooks/run-hook.mjs`. It stopped
because the providers not yet installed still pointed at the bash runtime. The copilot
run came last, found no provider on the old runtime, removed the 10 retired files, and
printed `Install verified for copilot (1.19.0)`. Re-running install for claude, codex,
and antigravity then printed `Install verified` for each, with exit 0.

The `install --dry-run` preview exited 0 for all four agents beforehand, so it does not
predict this failure. After the re-runs, every provider config references only the new
runtime: `.claude/settings.json` (search: "run-hook.mjs").

## Footgun: the Codex hook contract test pins goat-flow's hook file names

**Status:** active | **Created:** 2026-11-23 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After any goat-flow upgrade that changes hook registrations, run `uv run pytest tests/integration/test_hook_contract.py` and move its path literals to the installed runtime before running the full gate.
**Trigger phase:** VERIFY
**Incident count:** 1
**Latest occurrence:** 2026-11-23

`test_codex_registers_post_edit_quality_hook` asserts that the Codex `PostToolUse`
command names the quality hook and its launcher by file name. The 1.19.0 upgrade
renamed both, so the full suite reported `1 failed, 2938 passed` with
`assert '.goat-flow/hooks/gruff-code-quality.sh' in 'node -e ...'`. Neither the
installer, `goat-flow audit`, nor `hooks verify` reads project tests, so only
`uv run pytest` caught it. The literals now name `gruff-code-quality.mjs` and
`run-hook.mjs` in `tests/integration/test_hook_contract.py` (search: "run-hook.mjs").

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
`.codex/hooks.json` (search: `post-turn-safety.mjs`) with two identical
`Stop` entries where it previously had one, and `.codex/hooks.json` (search:
`post-turn-safety.mjs`) with two where it previously had none.
`hooks sync . --agent claude` collapsed claude back to a single entry. A later
`install . --agent claude --update-config-version` re-created the duplicate,
which is what proves the append happens on every install rather than only on
the version migration.

Duplicate Stop entries do not fail `goat-flow audit`, so nothing in the normal
verification trio reports them. Check the registration counts directly, or run
`hooks sync` unconditionally after install and re-read the config.

Not reproduced 2026-10-03 on goat-flow 1.17.0 or 2026-10-15 on goat-flow 1.18.0:
four sequential `install . --agent claude|codex|antigravity|copilot` runs left
exactly one `Stop` registration in `.claude/settings.json` and in `.codex/hooks.json`.
Not reproduced 2026-11-23 on goat-flow 1.19.0 either: re-running `install . --agent claude`
and `install . --agent codex` after the upgrade left one `Stop` entry in each file before
`hooks sync` ran. The `.sh` hook names in the 2026-08-11 measurement are now `.mjs`.

## Footgun: goat-flow install drops retired Claude denies without adding the new ones

**Status:** active | **Created:** 2026-10-03 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After any `goat-flow install` over an existing `.claude/settings.json`, diff its `permissions.allow` and `permissions.deny` lists against the installed package's Claude settings template and add the missing rules before running the harness audit.
**Trigger phase:** VERIFY
**Incident count:** 2
**Latest occurrence:** 2026-10-15

Upgrading 1.15.1 to 1.17.0, the installer edited the user-owned
`.claude/settings.json` in place. It removed the retired deny rules: the blanket
Bash denies for privileged and disk-wiping commands, and the Read/Edit denies for
`secrets/**` and `credentials*`. It did not add the 20 credential-store rules
that the 1.17.0 template ships for `.netrc`, `.pgpass`, `.git-credentials`,
`.config/gh/hosts.yml`, and gcloud; they now sit in `.claude/settings.json`
(search: "Read(~/.pgpass)") only because they were added by hand. A fresh
install seeds the full template, so only upgraded projects miss them.

`audit . --agent claude --harness` then failed `deny-covers-secrets` with
`missingPatterns: ["file-read-secret-paths"]`, because the audit requires the
four `~/` plaintext-store Read denies. Setting the deny list to the template's
list (72 rules, a strict superset of the upgraded file) cleared the failure.
The base audit and `--check-drift` both pass with the gap present.

Observed again 2026-10-15 upgrading 1.17.0 to 1.18.0: `install . --agent claude`
printed review guidance for `Read(**/credentials.json)` and `Edit(**/credentials.json)`
without adding them to `permissions.deny` or adding `Edit(.env.example)` and
`Edit(**/.env.example)` to `permissions.allow`; diffing `.claude/settings.json`
(search: "Read(**/credentials.json)") against the shipped template aligned both lists.

Not reproduced 2026-11-23 upgrading 1.18.0 to 1.19.0: after install, `permissions.allow`
(4 rules) and `permissions.deny` (74 rules) matched the package's
`workflow/hooks/agent-config/claude.json` template exactly, and nothing was dropped.

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
