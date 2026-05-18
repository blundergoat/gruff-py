---
category: verification
last_reviewed: 2026-05-18
---

## Lesson: Run targeted formatting before broad verification on dirty surfaces

**Created:** 2026-05-18
**Incident:** During M25, `uv run ruff format --check src tests` mixed a new
touched-file formatting issue with pre-existing unrelated formatting drift
outside the patch. The correction was to run `uv run ruff format` only on the
M25-touched files, then keep the repo-wide format check marked as blocked by
unrelated drift.

When a repo-wide non-mutating format check is already known to fail, run a
touched-file format check or formatter pass before the broad gate so the
agent-owned formatting state is separated from unrelated workspace drift.
