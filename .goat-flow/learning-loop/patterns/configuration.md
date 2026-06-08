---
category: configuration
last_reviewed: 2026-05-26
updated: 2026-05-26
---

## Pattern: Adding a top-level cross-impl config key

**Created:** 2026-05-26

**Context:** When a new top-level config key needs to ship in lockstep across
sibling gruff implementations (e.g. the family-wide `minimumSeverity:` block
landed in 0.1.2 per ADR-019), the key has to land cleanly across loader,
dataclass, init renderer, CLI consumers, validator, and docs in a single
cycle — and the cross-port contract must be locked before any one port
ships, or alias-vs-rename divergence becomes permanent.

**Approach:** Land the change in the following order so each step's
verification gate fires before the next step depends on it.

1. **Write the ADR first.** `.goat-flow/decisions/ADR-NNN-<topic>.md` records
   the precedence rule, the accept-sets for keys and values, the rejected
   alternatives (so future agents do not re-litigate them), the off-switch
   value (`none` not `never` for the family-wide invariant), and the
   cross-port coordination posture (who owns alignment, what happens if a
   sibling port ships first with a divergent value).
2. **Add the schema-version literal** in `src/gruffpy/analysis/schema.py`
   (search: `CONFIG_SCHEMA_VERSION`) and re-export from
   `src/gruffpy/analysis/__init__.py`. Pre-existing config files without
   the literal must be rejected on load — no back-compat shim, point users
   at `gruff-py init --force`.
3. **Extend `AnalysisConfig`** with the new field, a `with_<key>` helper
   (`src/gruffpy/config/analysis_config.py` search: `with_minimum_severity`),
   and a `BINARY_DEFAULTS` constant (search:
   `MINIMUM_SEVERITY_BINARY_DEFAULTS`) shared across loader, renderer, and
   any CLI precedence logic.
4. **Extend the validator** in `src/gruffpy/config/loader.py` (search:
   `_validate_minimum_severity`). Surface ALL key/value errors at once
   rather than bailing on the first — config errors are debugging surface,
   not adversarial input. Reject non-gating keys explicitly so silent
   acceptance can't become a CI footgun.
5. **Wire the CLI consumers** in `src/gruffpy/cli.py` (search:
   `was_fail_on_set_on_cli`) and `src/gruffpy/analysis/runner.py` (search:
   `config_severity_command`). Use `click.get_parameter_source` to
   distinguish a user-passed flag from Click's default-value fill-in, so
   the config value only overrides when the CLI is silent.
6. **Update the init renderer** in `src/gruffpy/command/init_config.py`
   (search: `_render_minimum_severity_block`) and the corresponding
   preservation helper (search: `existing_minimum_severity`) so
   `gruff-py init --force` preserves a user-tuned block byte-for-byte.
7. **Sweep the docs and CHANGELOG** in the same change:
   `docs/configuration.md` (search: `Severity Gate`),
   `docs/ci-integration.md`, `docs/dashboard.md`, `docs/reporting.md`,
   `docs/output-formats.md`, `README.md`, and a `[Unreleased]` section in
   `CHANGELOG.md` calling out the cross-port status note.
8. **Add the lockstep footgun** in
   `.goat-flow/footguns/compatibility.md` so future agents know which
   surfaces move together when the binary default changes.

**Verification:** Each step has a discrete test gate. Run
`uv run pytest tests/unit/config/test_<key>_precedence.py` after step 4 to
prove validator rejections fire; `uv run pytest tests/unit/command/test_init_config.py`
after step 6 to prove the round-trip preservation; `uv run pytest` plus
`uv run gruff-py analyse src/` after step 7 to prove the dogfood grade is
unchanged. The dogfood scan is the integration-level lockstep check —
self-inflicted drift surfaces here before the cross-port one does.

**Fixture-audit scope:** when step 4 introduces a hard validation requirement
(e.g. "every loaded config must declare `schemaVersion`"), the milestone-named
test files almost certainly understate the audit surface. Grep
`tests/` broadly for the construct the new validator gates on (e.g.
`grep -rln 'ConfigLoader\|tool\.gruff' tests/`) and update every inline YAML
or TOML fixture that does NOT explicitly assert the new rejection. 0.1.2 M02
listed two test files but the broader grep surfaced ~9 with affected
fixtures (`test_loader_precedence.py`, `test_init_config.py`,
`test_accepted_abbreviations_loader.py`, `test_dead_code_allowlist_loader.py`,
`test_docs_pillar_integration.py`, `test_cli_smoke.py`,
`test_perf_script_smoke.py`, plus the project's own dogfood `.gruff-py.yaml`).
The cheap upfront grep saves a debug-from-test-failure round-trip.

**Cross-port discipline:** Confirm the off-switch value and the accept-set
match every sibling port BEFORE the local change ships. Aliases are a
divergence trap (e.g. accepting `never` in gruff-py as an alias for `none`
freezes gruff-go's divergence rather than resolving it). Capture the
coordination posture in the ISSUE.md for the workstream so reviewers can
see who owns alignment.

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
