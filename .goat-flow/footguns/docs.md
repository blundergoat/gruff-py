---
category: docs
last_reviewed: 2026-05-18
---

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
