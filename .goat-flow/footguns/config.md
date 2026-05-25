---
category: config
last_reviewed: 2026-05-25
---

## Footgun: ConfigLoader `.get(key, [])` collapses absent into empty, clobbering seeded AnalysisConfig defaults

**Status:** active | **Created:** 2026-05-25 | **Evidence:** ACTUAL_MEASURED

Any new non-empty default added to an `AnalysisConfig` field that is also user-configurable under `[tool.gruff-py.allowlists]` (or another similarly-applied section) can be silently zeroed out by `ConfigLoader` when the user defines that section for an unrelated purpose. The pre-fix shape was `config.with_accepted_abbreviations(tuple(allowlists.get("acceptedAbbreviations", [])))` — when the key was absent, `.get(key, [])` returned `[]` and the `with_…()` setter unconditionally replaced the seeded default with `()`. Evidence anchors: `src/gruffpy/config/loader.py` (search: `_apply_present_allowlists`), `src/gruffpy/config/analysis_config.py` (search: `accepted_abbreviations: tuple[str, ...] = (`), and `tests/unit/config/test_accepted_abbreviations_loader.py` (search: `survive_unrelated_allowlists_section`).

Before adding a non-empty default to any `AnalysisConfig` field, grep `loader.py` for every callsite that reads the corresponding YAML/TOML key and confirm the loader only calls the matching `with_…()` setter when the key is actually present in the user's section. The fix shape is `if "<key>" in allowlists: config = config.with_…(tuple(allowlists["<key>"]))`. Adding tests that drive the loader with the unrelated section populated (e.g. `allowlists.secretPreviews` only) makes this regression observable in unit scope rather than via downstream rule misbehaviour.
