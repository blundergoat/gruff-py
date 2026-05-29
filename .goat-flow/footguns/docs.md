---
category: docs
last_reviewed: 2026-05-30
---

## Footgun: `architecture.md` / `README.md` rule counts and default-off claims drift from the live catalogue

**Status:** active | **Created:** 2026-05-30 | **Evidence:** ACTUAL_MEASURED
**Tags:** hallucination-risk: high

Hand-written rule-count summaries and capability claims in the docs go stale because the catalogue is the source of truth, not the prose. Measured 2026-05-30: `gruff-py list-rules --format json` reports **115** rules, but `.goat-flow/architecture.md` (search: `instantiates the full rule catalogue`) says "103 rules across 10 active pillars", and `README.md` says "116 rules" in one place (search: `rules across 11 pillars`) and "115" in another (search: `catalogue contains`). `architecture.md` (search: `ship default-off`) also claims "a subset of test-quality rules ship default-off" — but no rule sets `default_enabled=False`: `src/gruffpy/rule/definition.py` (search: `default_enabled: bool = True`) and a grep of `src/gruffpy/rule/` for `default_enabled=False` returns nothing.

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
