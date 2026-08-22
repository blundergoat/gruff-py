# ADR-007: Gitignore-aware source discovery

**Status:** Implemented
**Date:** 2026-05-16
**Updated:** 2026-08-23
**Ticket/Context:** Self-analysis of gruff-py surfaced findings in directories whose contents the project intentionally excludes from version control. The hardcoded `DEFAULT_IGNORED_DIRECTORIES` in `src/gruffpy/source/discovery.py` is not aligned with the project's existing source-of-truth for what counts as "the codebase": its `.gitignore`.

## Decision

`SourceDiscovery` will honor the project's `.gitignore` files (root plus any nested `.gitignore`s under the discovery roots) when deciding which files to scan. A path that is excluded by the project's git boundary is, by default, excluded from analysis.

The layered ignore semantics are:

1. **Configured ignore patterns** (`paths.ignore` in `.gruff.yaml` / `[tool.gruff-py.paths]`) are authoritative for every invocation shape.
2. **VCS internals** (`.git`, `.hg`, `.svn`) are always blocked, including for explicit files and `--include-ignored`.
3. **Gitignore exclusions** are read from the project's root and nested `.gitignore` files unless `--include-ignored` or an explicit file operand bypasses them.
4. **No-gitignore fallback directories** use the family list plus Python's cache and environment exceptions. They apply at any depth only when no `.gitignore` exists from the project root through the candidate's parent.

An extension-eligible explicit file bypasses Gitignore and fallback exclusions, but not configured policy or VCS internals. Lockfile names have no special exclusion: eligible forms such as `package-lock.json` are scanned, while `.lock` files remain unsupported by the existing file-type filter.

When no `.gitignore` governs a candidate, the shared fallback covers `.fleet`, `.idea`, `.vscode`, `build`, `coverage`, `dist`, `node_modules`, and `vendor`; Python additionally covers `.mypy_cache`, `.pyre`, `.pytest_cache`, `.pytype`, `.ruff_cache`, `.tox`, `.venv`, `__pycache__`, `htmlcov`, and `venv`.

`SourceDiscoveryResult.ignored_paths` continues to record what was skipped so reporters can surface it.

## Context

The scanner today maintains its own answer to "which directories aren't really part of the codebase" via `DEFAULT_IGNORED_DIRECTORIES`. That answer drifts from the project's `.gitignore` for every consumer project: any tooling, agent workspace, vendored output, or cache directory that the project gitignores but the scanner doesn't list is scanned anyway, producing findings on artifacts the project has explicitly declared out-of-scope.

Maintaining a parallel ignore list inside the scanner is a dead-end: every consumer project adds new tooling that the scanner cannot anticipate. The project already maintains a precise statement of "what is and isn't the codebase" - its `.gitignore`. Deferring to it eliminates the drift category entirely.

The trade-off is mainly about the security/sensitive-data pillars. Today those rules scan every file under the discovery root, which can catch credentials accidentally written into a directory that the scanner does not know about. After this ADR, those rules only see git-tracked files. For typical projects this is correct - secrets that aren't committed aren't a supply-chain risk and shouldn't dominate the report - and projects that need broader coverage can pass `--include-ignored` or remove the entry from `.gitignore`.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **Honor `.gitignore`, then use a no-gitignore family fallback and configured ignores** (accepted) | Secrets in gitignored files are not flagged during directory walks unless `--include-ignored` is used. Adds a gitignore parser to the runtime dependency graph. | Accepted: project policy owns every governed subtree, while rootless exports retain conservative shared defaults. Explicit supported files remain available for security review. |
| Keep the hardcoded `DEFAULT_IGNORED_DIRECTORIES` and require every project to extend it via `paths.ignore` | Scales linearly with how many tooling directories a project adopts; every new agent / IDE / framework needs a `paths.ignore` line per project. The scanner-side list never catches up. | Rejected: the drift problem is the reason this ADR exists. |
| Per-rule path scope (security/sensitive-data scan everything; structural rules respect gitignore) | Closer to the ideal split, but requires per-rule path configuration that does not exist in `RuleDefinition` today and is not part of the cross-impl config shape (ADR-006). | Rejected for now: would expand the config surface across gruff-py / gruff-php / gruff-ts. Revisit if the security-coverage regression turns out to matter in practice. |
| Honor `.gitignore` strictly and drop the fallback | Simpler model, but projects without a `.gitignore` lose obvious dependency, build, editor, and Python cache exclusions. | Rejected: the shared fallback keeps rootless exports usable without overriding any subtree where a project has expressed policy. |

## Consequences

- A gitignore matcher is added to the runtime. Preference is for a maintained library (`pathspec`) over a hand-rolled implementation, because gitignore syntax (negation, anchored patterns, trailing-slash directory matches, nested files, `**` wildcards) is easy to get subtly wrong. Crosses the Ask First dependency boundary in `CLAUDE.md`.
- `SourceDiscovery.discover` continues to expose `include_ignored`. It bypasses Gitignore and non-VCS fallback exclusions, but never configured ignores or VCS internals.
- `paths.ignore` in `.gruff.yaml` is unchanged and not bypassed by `--include-ignored` - it remains the user's explicit, intentional exclusion list.
- Cross-implementation scan inputs follow the ratified family contract; Python-only cache and environment entries remain named ecosystem exceptions.
- The JSON schemas (`gruff-py.analysis.v1`, `gruff-py.baseline.v1`) and finding fingerprints are unaffected - this changes which files reach the rules, not what the rules emit.

## Cross-implementation Tracking

All five ports adopt the same VCS, Gitignore-deference, explicit-file, lockfile,
and shared-fallback semantics. Ecosystem-only entries remain explicit rather
than becoming undeclared discovery drift.

## Reversibility

**Two-way door.** Reverting to the prior behavior requires removing the gitignore parsing path and the dependency. No on-disk format changes, no schema changes, no public-API changes for rule authors.

Revisit triggers:

- Empirical evidence that the security/sensitive-data pillars miss real findings because gitignored locations hold committed secrets (i.e. `.gitignore` was wrong, not the scanner) - in which case the `--include-ignored` workflow needs to become more prominent, or per-rule path scope is reopened.
- gruff-php or gruff-ts adopt incompatible discovery behavior that materially diverges across implementations.
- `pathspec` (or the chosen matcher) develops a security incident or maintenance gap.
