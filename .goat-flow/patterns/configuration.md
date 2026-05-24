---
category: configuration
last_reviewed: 2026-05-24
---

## Pattern: Keep generated config defaults synchronized across renderer, tests, and docs

**Context:** `gruff-py init` emits a concrete starter `.gruff-py.yaml`, not just
the in-memory `AnalysisConfig.from_registry()` defaults. When the init template
adds or removes starter `paths.ignore` entries, the generated file, round-trip
expectation, CLI smoke coverage, and `docs/configuration.md` example must move
together. Forced regeneration must also preserve any existing `paths.ignore`
entries so user-maintained exclusions are not wiped.

**Approach:** Put starter init-only values in `src/gruffpy/command/init_config.py`
as an explicit constant, assert them in `tests/unit/command/test_init_config.py`,
keep an integration assertion in `tests/integration/test_cli_smoke.py`, and
update the configuration reference examples in the same change. Cover `--force`
with a smoke test that proves existing ignore entries keep their order and
malformed ignore lists are left untouched.
