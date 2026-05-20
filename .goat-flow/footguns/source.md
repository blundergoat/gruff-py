---
category: source
last_reviewed: 2026-05-20
---

## Footgun: Gitignore ignored-parent guard cannot be removed for re-includes

**Status:** active | **Created:** 2026-05-20 | **Evidence:** ACTUAL_MEASURED

`GitignoreMatcher` needs both the ignored-parent early return and the contents-glob directory special case. Evidence anchors: `src/gruffpy/source/gitignore.py` (search: `ancestor_is_ignored is True`), `src/gruffpy/source/gitignore.py` (search: `endswith("/**")`), and `tests/unit/source/test_gitignore_contract.py` (search: `vendor/keep.py`).

The non-obvious failure mode is that removing the ancestor guard to support patterns like `/foo/**` plus `!foo/bar.py` lets nested `.gitignore` files inside truly ignored directories, such as `vendor/`, re-include children that Git still treats as ignored. Keep `tests/unit/source/test_gitignore_contract.py` in focused verification whenever changing gitignore traversal or re-include behavior.
