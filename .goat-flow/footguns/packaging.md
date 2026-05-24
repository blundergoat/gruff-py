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

## Footgun: Shell clean steps fail on the first build because dist/ is absent

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

`scripts/publish-pypi.sh` runs `clean_dist` before `uv build`, and `clean_dist`
calls `find "$DIST_DIR" -maxdepth 1 ...` directly. Evidence anchors:
`scripts/publish-pypi.sh` (search: `clean_dist()`) and `scripts/publish-pypi.sh`
(search: `build_package()`).

The non-obvious failure mode is that on a fresh clone (or after the user
deletes `dist/`), `find` prints `No such file or directory` and exits non-zero,
which trips `build_package`'s `|| return 1` before `uv build` is ever invoked.
A reproduction in an empty directory confirms `exit_code=1` from the same
`find` invocation. Any shell step that cleans a build-output directory must
`mkdir -p` it first or test `[[ -d "$dir" ]]` before invoking `find ... -delete`
so that the first-run path matches the steady-state path.
