---
category: setup
last_reviewed: 2026-05-13
---

## Lesson: Treat setup stats warnings as harness blockers

**Created:** 2026-05-13
**Incident:** During this setup, `goat-flow stats . --check` returned `"status": "pass"` while warning that `.goat-flow/lessons/` contained zero entries. The next `goat-flow audit . --agent claude --harness` failed `feedback-loop-active` on that empty lesson bucket.

When setup stats emits learning-loop warnings, resolve them before running the harness audit. A pass status with warnings can still predict a harness failure.
