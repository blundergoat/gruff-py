---
category: setup
last_reviewed: 2026-07-13
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
