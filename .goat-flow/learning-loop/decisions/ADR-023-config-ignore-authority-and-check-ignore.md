# ADR-023: Config `paths.ignore` is authoritative in every invocation mode; add `check-ignore`

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Matthew Hansen
**Ticket/Context:** Closes the coding-agent-hook correctness gap where a hook passing the agent's changed or explicit paths could surface findings for files the project deliberately excludes via `paths.ignore`. Extends [ADR-007](ADR-007-gitignore-aware-source-discovery.md) and serves the [ADR-022](ADR-022-reviewer-verification-mission.md) reviewer-verification mission. Coordinated with the workspace `CONTRACT.md` "Ignore Semantics" clause.

## Context

gruff-py is built to run as a coding-agent hook (ADR-022): after an agent edits files, a hook runs gruff on the changed code. Hooks pass explicit file paths or a diff, not a directory to walk. ADR-007 established three layered ignore filters — default-ignored directories, `.gitignore`, and config `paths.ignore` — with `paths.ignore` never bypassed by `--include-ignored`.

Verification for this change confirmed gruff-py **already** applies `paths.ignore` to explicit-arg and diff/changed-region invocations (both route through `SourceDiscovery.discover(..., configured_ignore_patterns=...)`, and `_ignore_decision` tests the configured pattern before the `include_ignored` short-circuit). The core authority was already correct — unlike some sibling ports. Two gaps remained:

1. Skipped paths were reported as bare strings (`ignoredPaths`) with no machine-readable reason. A hook could not tell *why* a file produced no findings — deliberately ignored, genuinely clean, or not an analysable source.
2. There was no way to ask "would gruff ignore this path?" without running a full analysis, so an agent hook had to analyse a file to discover it was out of scope.

## Decision

1. **`paths.ignore` is authoritative in every invocation shape** — directory walk, explicit file arguments, and all diff/changed-region modes (`--diff`, `--diff -`, `--changed-ranges`, `--since`). A matching path produces no findings however it is supplied. `--include-ignored` opts into default/gitignore paths only and never overrides `paths.ignore`. (Pre-existing; now locked by tests.)

2. **Skipped paths carry a reason.** The analysis JSON gains an additive `ignoredPathDetails` array — one object per skipped path with `source` (`config` | `gitignore` | `default` | `generated`) and the matched `pattern` (for `config`). The existing string `ignoredPaths` is unchanged, so the change is additive and `gruff-py.analysis.v1` is not bumped.

3. **A single ignore engine** backs both `analyse` and the new `check-ignore` command. `SourceDiscovery.classify(path)` returns the same decision discovery records, plus the generated-lockfile reason discovery otherwise applies via source-type filtering, so the two surfaces cannot diverge.

4. **New `check-ignore` command**: `gruff-py check-ignore [--format text|json] [--config <path>|--no-config] <path>...` reports, per path, whether gruff would ignore it and the matching `source` + `pattern`, performing no analysis. JSON `[{ "path", "ignored", "source", "pattern" }]` is the agent contract; exit codes mirror `git check-ignore` (`0` = at least one ignored, `1` = none, `2` = error).

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Additive `ignoredPathDetails` beside string `ignoredPaths` (accepted) | Two fields carry overlapping data. | **Accepted.** Backward-compatible: consumers reading the string list are unaffected; no schema-version bump, honouring the cross-impl `CONTRACT.md` schema-stability policy. |
| Change `ignoredPaths` elements from strings to objects | Breaks every consumer doing `for p in ignoredPaths`; forces a `gruff-py.analysis.v1` → v2 migration across ports. | Rejected — breaking, and the contract resists schema renames for cosmetic parity. |
| Duplicate the ignore logic inside `check-ignore` | A second glob/gitignore implementation drifts from discovery; `check-ignore` and `analyse` give different answers. | Rejected — `check-ignore` shares `SourceDiscovery`'s engine (single source of truth). |
| No `check-ignore`; let agents infer scope from empty findings | "Zero findings" is ambiguous (ignored vs clean vs unparseable); the hook wastes a full analysis to learn a file is out of scope. | Rejected — the explicit verdict is the point. |

## Consequences

- `SourceDiscoveryResult` gains `ignored_path_reasons` (parallel to `ignored_paths`); `AnalysisReport` gains `ignored_path_details`; the text reporter annotates the ignored-paths section with `(source: pattern)`. Finding fingerprints and the rest of the schema are untouched.
- `generated` (lockfiles in `IGNORED_FILENAMES`) surfaces through `check-ignore` even though discovery drops those files via source-type filtering rather than recording them in `ignoredPaths`; `analyse` output is unchanged.
- Cross-impl: the workspace `CONTRACT.md` "Ignore Semantics" clause makes `check-ignore` and ignore-authority a shared expectation. Diff flag spellings stay per-language; the authority rule applies to whichever diff forms an implementation exposes.

## Reversibility

**Two-way for the command and the field.** `check-ignore` and `ignoredPathDetails` are additive; removing them needs no on-disk migration. The ignore-authority guarantee is the behaviour ADR-007 already implied, now tested — reverting it would reopen the agent-hook correctness gap and contradict `CONTRACT.md`.

Revisit triggers:

- A sibling port adopts a different `check-ignore` JSON shape or `source` vocabulary — reconcile via `CONTRACT.md`.
- `generated` proves to need to appear in `ignoredPaths` / `analyse` output (not only `check-ignore`) for a real consumer.
