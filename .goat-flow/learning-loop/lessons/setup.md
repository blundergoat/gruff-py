---
category: setup
last_reviewed: 2026-08-14
---

## Lesson: Treat setup stats warnings as harness blockers

**Created:** 2026-05-13
**Incident:** During this setup, `goat-flow stats . --check` returned `"status": "pass"` while warning that `.goat-flow/learning-loop/lessons/` contained zero entries. The next `goat-flow audit . --agent claude --harness` failed `feedback-loop-active` on that empty lesson bucket.

When setup stats emits learning-loop warnings, resolve them before running the harness audit. A pass status with warnings can still predict a harness failure.

## Lesson: Verify safety flags per uv subcommand

**Created:** 2026-07-13
**Incident:** During the GOAT Flow 1.13.1 setup toolchain probe, `uv lock
--check` correctly reported that the project lock needed an update. To keep the
unrelated lock boundary untouched, the agent then tried `uv build --locked`,
assuming the lock-safety flag available on other uv workflows also applied to
`build`. uv 0.10.9 rejected it with `unexpected argument '--locked' found`.
After reading `uv build --help`, the corrected probe used `uv build --offline`;
it built both distributions successfully, and the SHA-256 of `uv.lock` remained
`59553bfcfa63a36704c4345f1630f381eba4a9857b832e1c86d8640f4c3806b5`
before and after.

Do not infer uv flags across subcommands. Read `uv <subcommand> --help` before
adding a safety option, and prove a build did not mutate a protected lockfile by
capturing its hash before and after. Use `--offline` only to constrain network
access; it is not a substitute for a lock-enforcement flag.

## Lesson: Run setup audit variants as one coupled gate

**Created:** 2026-08-08
**Decision changed:** After any setup-document fix or observed dirty-path change, rerun the base, harness, and content audits together before treating any individual pass as final.
**Trigger phase:** VERIFY
**Incident count:** 1
**Latest occurrence:** 2026-08-08
**Incident:** During the GOAT Flow 1.15.0 refresh, the first base and harness audits passed while the content audit found 11 setup warnings: a missing architecture anchor, stale orientation facts, and omitted playbook inventories. After those warnings were fixed, the content audit passed. The required full trio then caught a stale `AGENTS.md` commit-guide pointer because a staged guide rename had appeared during the audit cycle. Base and content remained green; only the harness detected the unresolved path. Updating the pointer and rerunning all three audits produced three passes against one filesystem state.

Treat the three audit variants as one verification unit because their evidence is complementary. Before each bounded rerun, capture `git status --short`; if the dirty-path set changed, re-read affected references before interpreting a failure or attributing the mutation. Close the setup gate only when base, harness, and content all pass without another intervening write.

## Lesson: Instruction-file path references resolve from the project root

**Created:** 2026-08-08
**Decision changed:** Write every backticked path in an instruction file as a full project-root-relative path, even when the surrounding prose already names its directory.
**Trigger phase:** VERIFY
**Incident count:** 1
**Latest occurrence:** 2026-08-08
**Incident:** A router-table row in `CLAUDE.md` was extended to say that `writing-style.md` binds human-read output. The row already pointed at `.goat-flow/skill-docs/playbooks/`, so the bare filename read correctly to a human. The same edit was mirrored into `.github/copilot-instructions.md`. Both agents then failed `audit --harness` on `doc-paths-resolve`, which reported 117 of 118 paths resolved with the single unresolved ref recorded as `writing-style.md` from `CLAUDE.md`; the base and content audits stayed green and named nothing. Rewriting both refs as `.goat-flow/skill-docs/playbooks/writing-style.md` returned 118 of 118 and passed the harness for claude, copilot, and codex.

The checker treats a backticked ref as a path from the repository root and has no notion of the row it sits in, so adjacency to the owning directory buys nothing. Neither the base nor the content audit catches this, which is why the harness variant has to run after any router-table or Key Resources edit. When a check reports one unresolved ref, read the `details.docPaths.unresolved` entry for the literal `ref` and `source` rather than re-reading the whole table.

## Lesson: Check the sibling ports before deleting local divergence an audit calls stale

**Created:** 2026-08-14
**Decision changed:** Before removing local config an audit calls stale, check sibling intent and the current provider contract; a template difference alone proves neither safety nor error.
**Trigger phase:** SCOPE
**Incident count:** 1
**Latest occurrence:** 2026-08-14
**Incident:** `goat-flow audit . --agent claude --harness` failed `settings-rules-matched`, reporting 20 `Write(...)` deny rules in `.claude/settings.json` as "unmatched rule form - Edit(path) covers file edits". Three checks appeared to confirm they were safe to delete: `deny-covers-secrets` still passed, `grep -rln 'Write(\*\*/\.env)' node_modules/@blundergoat/goat-flow/` found no shipped template containing them, and the commit that added them (`51d9db4`) was titled for an unrelated SSRF fix and documented nothing in `CHANGELOG.md`. Eight rules were deleted before a read of the sibling gruff-go port's 1.15.1 feedback report showed gruff-go had made the identical deletion and reverted it. That port's changelog entry (search: "The Claude permission profile denies secret writes again") records the same rule set as a deliberate divergence, added because the template gates `Read` and `Edit` while the only `PreToolUse` hook matches `Bash`, leaving the `Write` tool ungated. Its own Claude settings still carry 21 such rules. Here `.claude/settings.json` was restored and proven byte-identical to HEAD by md5.

Every signal available inside one port pointed the wrong way, because they all measured agreement with the template rather than intent. "Not in the shipped template" is the definition of divergence, so it cannot also be evidence that the divergence is accidental. The workspace rule that a change to one port is incomplete until the other four are checked applies in reverse too: before removing a port's local security divergence, grep the siblings and their changelogs for the same shape. An undocumented commit is weaker evidence of accident than a sibling's documented decision is of intent.

**Follow-up evidence (2026-08-14):** [Claude Code's permissions reference](https://code.claude.com/docs/en/permissions) (search: `Claude Code checks file permissions against Edit(path) and Read(path) rules only`) says versions 2.1.228 and newer check writes against `Edit(path)` and `Read(path)`; `Write(path)` rules are accepted but never consulted. It also states that a matching `Read` deny blocks Edit and Write, including file creation. The local `claude --version` returned `2.1.232 (Claude Code)`.

This primary provider evidence resolves the uncertainty that stopped the first removal. The gruff-go rationale does not apply to the installed version: the existing `Read` and `Edit` rules enforce the protected paths, while the duplicate `Write(path)` rules add warnings without protection. The sibling check remains mandatory, but current versioned provider evidence decides whether an intentional divergence works.
