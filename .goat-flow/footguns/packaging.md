---
category: packaging
last_reviewed: 2026-05-24
---

## Footgun: Hatchling sdist can include ignored local workspace artifacts

**Status:** active | **Created:** 2026-05-20 | **Evidence:** ACTUAL_MEASURED
**hallucination-risk:** high

Hatchling's source distribution selection can include files that are local-only
or ignored by nested project workspace rules unless the sdist target excludes
them explicitly. Evidence anchors: `pyproject.toml` (search:
`[tool.hatch.build.targets.sdist]`) and `docs/releasing.md` (search:
`Confirm screenshots or dashboard artifacts are not accidentally committed`).

The observed failure mode was `uv build` producing
`dist/gruff_py-0.1.0.tar.gz` with `.goat-flow/scratchpad/` analysis JSON,
dashboard screenshots, session logs, agent configuration, and npm metadata.
The wheel stayed clean, so checking only the wheel would miss the publish risk.

Prevention: after packaging changes and before release, run `uv build` and then
verify the sdist with a negative grep for `.agents`, `.claude`, `.codex`,
`.goat-flow`, `AGENTS.md`, `CLAUDE.md`, `node_modules`, `package-lock.json`,
`package.json`, and `perf-out`.
