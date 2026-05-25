# ADR-018: Retire `naming.parameter-type-name`

**Status:** Accepted
**Date:** 2026-05-25
**Cross-implementation pair:** `gruff-php/.goat-flow/decisions/ADR-014-retire-naming-parameter-type-name.md` (same decision in the sibling port).

## Decision

`naming.parameter-type-name` is removed from gruff-py. The rule module, every test that targets the rule (`tests/unit/rule/naming/test_parameter_type_name_rule.py`), the rule's registration in `src/gruffpy/rule/catalog.py`, the rule's entry in `docs/rules.md`, and the project's `.gruff-py.yaml` block for the rule (and its entry in the `selection.rules` list) are all deleted in the same change.

Adjacent rules whose docstrings reference the deleted rule (`naming.short-variable`, the `accepted_abbreviations` comment in `AnalysisConfig`, the rule-list assertion in `test_naming_pillar_integration.py`) are updated to drop the dangling reference. The cross-port sibling rule in gruff-php is retired in lockstep.

## Context

The rule enforced that parameters annotated with a Title-cased class-like type use the snake_case form of the type root (e.g. `def f(repository: Repository)` rather than `def f(repo: Repository)`). In a typed Python codebase the annotation itself shows the type at the call site, so the rule's "expected name" was essentially restating the type — the same pattern the project's own observation discipline argues against in source code.

Concrete signal observed during the 2026-05-25 expansion of `ignoredTypes` / `ignoredParameterNames` defaults in the PHP sibling:

- A real PHP codebase (the data carries to gruff-py because the rule semantic is identical) produced **454 rule findings**.
- Roughly **44 (≈10%)** were universal false positives now silenced by defaults: date/time semantic-role names (`now`, `created_at`, `expires_at`, …) and exception conventions (`e`, `exception`, `previous`, `cause`).
- The remaining **~410 findings** were domain-DTO naming complaints — the rule wanting `session: BookingSession` renamed to `booking_session: BookingSession`. Modern Python teams routinely name domain parameters by role rather than by type.

Other pressure specific to the Python implementation:

- The `_DEFAULT_IGNORED_TYPES` constant grew to **26 entries** (date/time × 5, async iterators × 4, sync iterators × 3, IO/streams × 4, callable/typing × 5, exceptions × 2, identifiers × 1, decimal × 1, plus `Any`). The list is essentially the typing-stdlib surface plus the most popular ecosystem libraries (pendulum's `DateTime`/`Date`/`Duration`/`Period`, `pydantic.BaseModel` was on deck).
- `_ignored_parameter_names()` had two code paths (the loader-merged value, and a test-only fallback that needs to stay in lockstep with the rule's `default_options["ignoredParameterNames"]`) — both updated when the defaults changed. This duplication was a maintenance hazard.
- `_expected_name`, `_union_expected_name`, and `_expected_parameter_name` all carry an `ignored_types: frozenset[str]` parameter purely to plumb the new option through the recursive walk. Removing the rule removes the whole plumbing.
- The `accepted_abbreviations` field on `AnalysisConfig` (`src/gruffpy/config/analysis_config.py`) carried a comment "Consumed by `naming.abbreviation` and `naming.parameter-type-name`" — half of that comment becomes a lie after removal. The remaining consumer (`naming.abbreviation`) is unaffected.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| A. Keep adding exceptions (status quo) | `_DEFAULT_IGNORED_TYPES` grows monotonically as Python's typing surface and ecosystem libraries evolve; `_ignored_parameter_names()` fallback must stay in lockstep with `default_options`; `_expected_name` recursion plumbing carries an option that exists only to suppress its own rule. | Rejected. Maintenance arms race; the test-fallback / default-options coupling is a foot-gun (two failing tests in the 2026-05-25 batch caught one such drift). |
| B. Flip to opt-in (`default_enabled=False`) | The rule module, fixtures, and tests stay in the codebase for a feature most users won't run; the test-fallback / default-options coupling stays; integration test in `test_naming_pillar_integration.py` still needs the rule listed somewhere. | Rejected. Dead-code maintenance burden outweighs the benefit. |
| C. Invert the matching contract (new `enforced_types` / `enforced_module_prefixes` allowlist) | New option shape needed; rule does nothing by default; existing adopters lose findings silently; tests and fixtures need rewrite. | Rejected for now. Cleanest design but worth re-deriving from scratch if a real demand re-emerges. |
| D. Delete the rule and its scaffolding | Adopters lose enforcement of domain-DTO naming consistency; a handful of cross-references in docstrings / integration tests / docs need cleanup. | **Accepted.** Smallest persistent surface; revivable as a different design later. |

## Consequences

- The py rule catalogue drops one entry under the `naming` pillar. `docs/rules.md` is regenerated (see `python -m gruffpy.command.rule_docs` or whatever the project's regeneration entry point is).
- `RuleRegistry.defaults()` (via `src/gruffpy/rule/catalog.py`) no longer registers the rule. `AnalysisConfig.from_registry()` therefore does not seed a `RuleSettings` entry for it, which removes the `naming.parameter-type-name` block from init-generated `.gruff-py.yaml`.
- The project's own `.gruff-py.yaml` loses its `naming.parameter-type-name` block (the `selection.rules` mention at line ~98 and the per-rule options block at line ~331). Existing adopters get a one-line `git status` after `gruff-py init --force` runs; release notes call this out.
- `tests/unit/rule/naming/test_naming_pillar_integration.py` drops the rule from its expected-rules list; the comment about "parameter-type-name should NOT fire (repo is a prefix of repository)" is removed because the scenario it documented is no longer relevant.
- `scripts/performance-baselines/linux-x86_64.json` still references the deleted module path in its `topModulesMs` snapshot. That JSON is a measurement, not source-of-truth; the next regeneration drops the entry naturally. No code change needed.
- `src/gruffpy/config/analysis_config.py` comment for `accepted_abbreviations` is updated to mention only `naming.abbreviation`.

## Reversibility

**Two-way door, but with cleanup cost.**

- The rule module, fixture-equivalent test cases, and the option-merging plumbing are removed in this change. Reviving the rule by `git revert` is straightforward; re-implementing without a revert requires the prior `default_options` shape captured here:
  - `ignoredParameterNames`: union of `DEFAULT_NAMING_ABBREVIATIONS` (cross-rule abbreviation set) and ~30 universal semantic-role names (date/time roles, exception conventions). See the deleted `_DEFAULT_IGNORED_PARAMETER_NAMES` tuple in the prior `parameter_type_name_rule.py` commit for the canonical list.
  - `ignoredTypes`: 26 entries — see deleted `_DEFAULT_IGNORED_TYPES` tuple.
- Test helper plumbing in `_ctx()` would need its own fallback restored — see prior `_ignored_parameter_names()` and `_ignored_types()` helpers.

**Revisit trigger:** if a project surfaces a recurring ask for cross-team naming consistency on domain types, re-derive a new rule using **Option C** (inverted contract: `enforced_module_prefixes=['myapp.domain.*']`) rather than reviving the deleted shape. The exception-list-maintenance pattern is what failed; the underlying problem is still a legitimate ask.
