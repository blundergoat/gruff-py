# ADR-007: Gitignore-aware source discovery

**Status:** Implemented
**Date:** 2026-05-16
**Ticket/Context:** Self-analysis of gruff-py surfaced findings in directories whose contents the project intentionally excludes from version control. The hardcoded `DEFAULT_IGNORED_DIRECTORIES` in `src/gruffpy/source/discovery.py` is not aligned with the project's existing source-of-truth for what counts as "the codebase": its `.gitignore`.

## Decision

`SourceDiscovery` will honor the project's `.gitignore` files (root plus any nested `.gitignore`s under the discovery roots) when deciding which files to scan. A path that is excluded by the project's git boundary is, by default, excluded from analysis.

The layered ignore semantics become:

1. **Default-ignored directories** (built-in list of caches, venvs, vendored deps). Unchanged. Always-on unless `--include-ignored` is passed.
2. **Gitignore exclusions** (new). Read from the project's `.gitignore` files. Default-on unless `--include-ignored` is passed.
3. **Configured ignore patterns** (`paths.ignore` in `.gruff.yaml` / `[tool.gruff-py.paths]`). Unchanged. Layered on top.

A path is scanned iff it passes all three filters. `--include-ignored` continues to bypass the first two; the third stays user-controlled and is not overridden by the flag.

When no `.gitignore` exists, the scanner behaves exactly as before — there is no new requirement on consumer projects.

`SourceDiscoveryResult.ignored_paths` continues to record what was skipped so reporters can surface it.

## Context

The scanner today maintains its own answer to "which directories aren't really part of the codebase" via `DEFAULT_IGNORED_DIRECTORIES`. That answer drifts from the project's `.gitignore` for every consumer project: any tooling, agent workspace, vendored output, or cache directory that the project gitignores but the scanner doesn't list is scanned anyway, producing findings on artifacts the project has explicitly declared out-of-scope.

Maintaining a parallel ignore list inside the scanner is a dead-end: every consumer project adds new tooling that the scanner cannot anticipate. The project already maintains a precise statement of "what is and isn't the codebase" — its `.gitignore`. Deferring to it eliminates the drift category entirely.

The trade-off is mainly about the security/sensitive-data pillars. Today those rules scan every file under the discovery root, which can catch credentials accidentally written into a directory that the scanner does not know about. After this ADR, those rules only see git-tracked files. For typical projects this is correct — secrets that aren't committed aren't a supply-chain risk and shouldn't dominate the report — and projects that need broader coverage can pass `--include-ignored` or remove the entry from `.gitignore`.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **Honor `.gitignore` plus the existing default list and configured ignores** (accepted) | Secrets in gitignored files are not flagged unless `--include-ignored` is used. Adds a gitignore parser to the runtime dependency graph. | Accepted: drift between the scanner's idea of "the codebase" and the project's own `.gitignore` is the larger and more recurring problem. Local-only artifacts dominate findings on most real projects today. |
| Keep the hardcoded `DEFAULT_IGNORED_DIRECTORIES` and require every project to extend it via `paths.ignore` | Scales linearly with how many tooling directories a project adopts; every new agent / IDE / framework needs a `paths.ignore` line per project. The scanner-side list never catches up. | Rejected: the drift problem is the reason this ADR exists. |
| Per-rule path scope (security/sensitive-data scan everything; structural rules respect gitignore) | Closer to the ideal split, but requires per-rule path configuration that does not exist in `RuleDefinition` today and is not part of the cross-impl config shape (ADR-006). | Rejected for now: would expand the config surface across gruff-py / gruff-php / gruff-ts. Revisit if the security-coverage regression turns out to matter in practice. |
| Honor `.gitignore` strictly and drop `DEFAULT_IGNORED_DIRECTORIES` | Simpler model, but projects without a `.gitignore` (or with a thin one) lose the obvious cache/venv exclusions that the hardcoded list provides today. | Rejected: keeping the hardcoded list as a floor is cheap and makes the default behavior reasonable even on projects whose `.gitignore` is incomplete. |

## Consequences

- A gitignore matcher is added to the runtime. Preference is for a maintained library (`pathspec`) over a hand-rolled implementation, because gitignore syntax (negation, anchored patterns, trailing-slash directory matches, nested files, `**` wildcards) is easy to get subtly wrong. Crosses the Ask First dependency boundary in `CLAUDE.md`.
- `SourceDiscovery.discover` continues to expose `include_ignored`, and `--include-ignored` on the CLI continues to mean "scan default-ignored paths too." The flag is extended to also bypass gitignore. The same flag controls both because users who want to scan local-only files virtually always want to scan caches too.
- `paths.ignore` in `.gruff.yaml` is unchanged and not bypassed by `--include-ignored` — it remains the user's explicit, intentional exclusion list.
- Cross-impl note: gruff-php and gruff-ts use the same `.gruff.yaml` config shape (ADR-006). If they do not honor `.gitignore`, the same project will produce different file sets between implementations. This is acceptable for findings (the cross-impl contract is `gruff-py.analysis.v1` / `gruff-py.baseline.v1` / fingerprints, not "same files in the report"), but the divergence should be surfaced in their respective decision logs so the implementations converge over time.
- The JSON schemas (`gruff-py.analysis.v1`, `gruff-py.baseline.v1`) and finding fingerprints are unaffected — this changes which files reach the rules, not what the rules emit.

## Cross-implementation Tracking

gruff-php and gruff-ts should either adopt the same layered discovery semantics
or explicitly document why their source-discovery boundary differs. Until then,
shared config can still produce different file sets across implementations even
when report schemas and fingerprints remain compatible.

## Reversibility

**Two-way door.** Reverting to the prior behavior requires removing the gitignore parsing path and the dependency. No on-disk format changes, no schema changes, no public-API changes for rule authors.

Revisit triggers:

- Empirical evidence that the security/sensitive-data pillars miss real findings because gitignored locations hold committed secrets (i.e. `.gitignore` was wrong, not the scanner) — in which case the `--include-ignored` workflow needs to become more prominent, or per-rule path scope is reopened.
- gruff-php or gruff-ts adopt incompatible discovery behavior that materially diverges across implementations.
- `pathspec` (or the chosen matcher) develops a security incident or maintenance gap.
