---
category: configuration
last_reviewed: 2026-05-25
---

## Pattern: Split scaffold-via-`yaml.safe_dump` and rules-via-manual-string when init output needs per-rule comments

**Created:** 2026-05-25

**Context:** `render_default_config_yaml` originally built one Python dict (paths + allowlists + selection + rules) and round-tripped it through `yaml.safe_dump(document, sort_keys=False, default_flow_style=False)`. That works until you want a `# {description}` line above every rule entry — PyYAML's `safe_dump` has no API for emitting comments mid-document. Workarounds (post-process the dumped string with regex; swap to `ruamel.yaml`'s round-trip dumper) trade one bag of edge cases for another and pull in dependencies the project does not otherwise need.

**Approach:** Render the file in two pieces and concatenate, mirroring the `gruff-php` `InitCommand` split.

1. **Scaffold via `yaml.safe_dump`** — `src/gruffpy/command/init_config.py` (search: `_scaffold_document`) keeps the dict-based path for `minimumPythonVersion`, `paths`, `allowlists`, `selection`. These have static shapes and benefit from PyYAML's quoting / list formatting logic.
2. **Rules section by hand** — `src/gruffpy/command/init_config.py` (search: `_render_rules_section`) iterates `config.rules` in sorted id order, emits `  # {description-or-rule-id}` (descriptions resolved once up-front via `{rule.definition().id: rule.definition().get_description() for rule in registry.all()}`), then calls `yaml.safe_dump({rule_id: entry}, indent=2, …)` per rule and prefixes every output line with two spaces to nest under `rules:`.
3. **Concatenate** — `_HEADER + scaffold_yaml + rules_yaml` in `render_default_config_yaml`.

**Why per-rule dump rather than one large manual builder:** `yaml.safe_dump` of a single rule entry stays in lockstep with whatever option/threshold shapes the registry adds later (ints, floats, nested dicts, string lists). A hand-written formatter would have to re-implement that switch and drift as new option shapes appear. The wrapper only owns the comment line and the two-space indent.

**Round-trip contract:** `tests/unit/command/test_init_config.py` (search: `test_render_default_config_yaml_round_trips_through_loader`) asserts `loaded == defaults` after writing the rendered YAML to disk and loading it back. Any value that init seeds (e.g. `accepted_abbreviations`) must also be the default in `AnalysisConfig` itself, otherwise `loaded.accepted_abbreviations = seed` but `defaults.accepted_abbreviations = ()` and the equality fails. When extending the init seed for a non-path field, change `src/gruffpy/config/analysis_config.py` (search: `accepted_abbreviations: tuple[str, ...]`) at the same time — keep `from_registry()` defaults and init output in lockstep.

**Verification:** `uv run pytest tests/unit/command/test_init_config.py` covers the round-trip, registry parity, ignore preservation, and `from_registry` defaults end-to-end. Comments are invisible to `yaml.safe_load`, so the parse-based assertions naturally tolerate the comment lines `_render_rules_section` injects.

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
