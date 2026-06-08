---
category: docs
last_reviewed: 2026-05-31
---

## Footgun: `architecture.md` / `README.md` rule counts and default-off claims drift from the live catalogue

**Status:** active | **Created:** 2026-05-30 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

Hand-written rule-count summaries and capability claims in the docs go stale because the catalogue is the source of truth, not the prose. Measured 2026-05-30: `gruff-py list-rules --format json` reports **115** rules, but `.goat-flow/architecture.md` (search: `instantiates the full rule catalogue`) says "103 rules across 10 active pillars", and `README.md` says "116 rules" in one place (search: `rules across 11 pillars`) and "115" in another (search: `catalogue contains`). `.goat-flow/decisions/ADR-021-reviewability-profile.md` (search: `some `test-quality` members ship default-off`) also claims a subset of test-quality rules ship default-off — but no rule sets `default_enabled=False`: `src/gruffpy/rule/definition.py` (search: `default_enabled: bool = True`) and a grep of `src/gruffpy/rule/` for `default_enabled=False` returns nothing.

The non-obvious failure mode is that an agent reading these docs for rule facts (catalogue size, the default-off set) reasons from stale numbers — e.g. assuming it can opt-out a "default-off" test-quality rule that is actually default-on, or mis-stating the count in release notes. Verify rule facts against `gruff-py list-rules` / `RuleRegistry.defaults()`, never the prose. When a milestone changes the count (`.goat-flow/tasks/1.0.0/M01-*` removes npath → 114; M05/M06 add rules), reconcile all three doc surfaces in one pass.

## Footgun: Docs parameter rules treat leading cls as an implicit receiver

**Status:** active | **Created:** 2026-05-18 | **Evidence:** OBSERVED

`src/gruffpy/rule/docs/_helpers.py` (`signature_param_names`) intentionally
removes a leading `self` or `cls` parameter before docstring matching. That
policy also applies to module-level helper functions whose first parameter is
named `cls`.

The non-obvious failure mode is that adding an `Args:` entry for a standalone
helper's leading `cls` parameter creates `docs.stale-param-doc`, even though the
Python function signature contains that parameter. Evidence observed while
documenting `src/gruffpy/rule/_python_dynamism.py` (`has_framework_base` and
`has_dataclass_decorator`): the fix was to document the return value and omit
the `cls` parameter entry.

## Footgun: Committed docs cite milestone/task codes that point into the gitignored tasks dir

**Status:** active | **Created:** 2026-05-31 | **Evidence:** ACTUAL_MEASURED

Tracked docs across the repo cite milestone codes (`M01`, `M22`, `M33+M34+M35`,
etc.) as if they were stable references, but the task files those codes name
live under `.goat-flow/tasks/`, which is fully gitignored. Verified 2026-05-31:
`git check-ignore -v .goat-flow/tasks/0.3.0/<file>.md` matches
`.goat-flow/tasks/.gitignore:3:*`, and `git ls-files --error-unmatch` on the
same path fails ("did not match any file(s) known to git"). A
`git grep -lE '\bM[0-9]+[a-z]?\b'` over tracked files (excluding the gitignored
tasks dir and the goat-plan skill files that *teach* the `M<NN>-<slug>`
convention) returns **28 files**: 18 under `.goat-flow/decisions/`, 5 under
`.goat-flow/footguns/` (this file included — `M01-*`, `M05/M06` near search:
`reconcile all three doc surfaces`), 2 under `.goat-flow/lessons/`,
`.goat-flow/patterns/configuration.md`, and the test docstrings in
`tests/unit/finding/test_stable_identity.py` (search: `M05 lands`) and
`tests/unit/rule/test_explain_metadata.py` (search: `explain-mode metadata`).

The non-obvious failure mode is twofold. For a cloner, the reference is a dead
pointer — they get the doc but not the `M22` file, so the rationale citation
resolves to nothing and rots as milestone numbering is renumbered or retired.
For an agent, citing a milestone code reads as a durable anchor when it is a
gitignored process label; the same content should anchor on the stable artefact
instead (an `ADR-0NN` id, a rule ID, a file path with a `(search: "...")`
anchor, or a prose description of *what changed*). Stable ADR ids ARE allowed —
they are tracked decision docs with permanent identifiers. This is the
content-level corollary of the self-documenting-names rule (which bans milestone
codes in file/folder/identifier *names*): do not cite them in committed code or
doc *bodies* either. When editing any tracked doc, replace milestone-code
citations you touch with the stable anchor; leave the goat-plan skill files
alone, since their job is to document the naming convention itself.
