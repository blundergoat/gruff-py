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

## Footgun: Shell clean steps must tolerate missing build output directories

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

`find <dir> -delete` exits non-zero when `<dir>` does not exist. Any clean
step that pipes `find` failure into `|| return 1` will block the build on a
fresh clone or after a manual `rm dist/`. Evidence anchor:
`scripts/publish-pypi.sh` (search: `clean_dist()`) keeps the fixed pattern:
`mkdir -p "$DIST_DIR"` before `find ... -delete`.

Before adding a new clean step that targets a build-output directory, either
`mkdir -p` it first or guard with `[[ -d "$dir" ]]` so the first-run path
matches the steady-state path. A reproduction in an empty directory
(`exit_code=1` from `find dist/ -maxdepth 1 -delete`) is enough to confirm
the trap.

## Footgun: publish gates must not assume publish-before-tag release order

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

The release workflow tags before publishing. A publish preflight that rejects
existing local or remote Git tags will block the intended path even when the
version is not on PyPI yet. Evidence anchors: `scripts/publish-pypi.sh`
(search: `--require-unpublished-pypi`), `scripts/preflight-checks.sh` (search:
`version_exists_on_pypi`), and `docs/releasing.md` (search:
`Tag and push the release commit before publishing`).

For publish safety, check the package index for an already-used version rather
than treating `v<version>` as proof of publication. Git tags are release
provenance in this project, not the PyPI availability source of truth.

## Resolved Entries

## Footgun: clean_dist failed first-run publishes when dist/ was absent

**Status:** resolved | **Created:** 2026-05-24 | **Resolved:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

Historical trap: `scripts/publish-pypi.sh` ran `clean_dist` before `uv build`
without ensuring `dist/` existed first. On a fresh clone, `find dist/ -maxdepth
1 -type f ...` returned exit code 1, which trips `build_package`'s
`|| return 1` and aborted the publish before `uv build` was ever invoked.

Resolved on 2026-05-24 by prepending `mkdir -p "$DIST_DIR"` inside
`clean_dist`. The active footgun above keeps the broader rule (clean steps
must tolerate a missing target directory) discoverable for future scripts.
