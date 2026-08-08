---
category: setup
last_reviewed: 2026-08-08
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
