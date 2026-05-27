# ADR-019: Per-Command `minimumSeverity:` Config Dimension

**Status:** Accepted
**Date:** 2026-05-26
**Cross-implementation pair:** `gruff-go/.goat-flow/decisions/ADR-010-per-command-minimum-severity.md` (planned; gruff-go's current 0.1.2 draft still ships `never` as the off-switch value and needs to flip to `none` to match this ADR).
**Ticket/Context:** `.goat-flow/tasks/0.1.2/ISSUE.md`; wording-brainstorm critique at `gruff-go/.goat-flow/logs/critiques/2026-05-26-config-wording-brainstorm-b5k2x.md`.

## Decision

Introduce a flat top-level `minimumSeverity:` block in both `.gruff-py.yaml` and `[tool.gruff-py]` in `pyproject.toml`. The block is a per-command override for each gateable subcommand's `--fail-on` default. Keys are subcommand names; values are the four canonical fail thresholds.

```yaml
schemaVersion: gruff-py.config.v0.1
minimumSeverity:
  analyse: advisory
  report: none
  dashboard: none
```

```toml
[tool.gruff-py]
schemaVersion = "gruff-py.config.v0.1"

[tool.gruff-py.minimumSeverity]
analyse = "advisory"
report = "none"
dashboard = "none"
```

**Precedence (highest wins):**

1. `--fail-on <value>` passed on the command line.
2. `minimumSeverity.<command>` resolved from `.gruff-py.yaml` or `[tool.gruff-py.minimumSeverity]`.
3. Binary default for the subcommand (`analyse` = `advisory`; `report` and `dashboard` = `none`).

**Accept-sets (case-sensitive, no aliases):**

- Keys: exactly `{"analyse", "report", "dashboard"}`. Any other key — including the non-gating subcommands (`summary`, `list-rules`, `metric-calibration`, `init`, `list`, `help`, `completion`) and any typo — is rejected with a validator error that lists the accept-set verbatim.
- Values: exactly `{"advisory", "warning", "error", "none"}`. The validator surfaces all bad keys and bad values in one pass (no first-error bail-out).

**Schema version literal:** a new module-level constant `CONFIG_SCHEMA_VERSION = "gruff-py.config.v0.1"` is added to `src/gruffpy/analysis/schema.py` and re-exported from `src/gruffpy/analysis/__init__.py`. Config files without a top-level `schemaVersion:` field are rejected on load; the error points at `gruff-py init --force`. There is no implicit default and no back-compat shim for pre-0.1.2 config files.

**Default flip:** `analyse`'s binary `--fail-on` default changes from `error` to `advisory`. `report` and `dashboard` keep `none`.

## Context

Three problems converged in 0.1.2:

1. **No per-project default-threshold control.** Today every user must pass `--fail-on` on the command line. There is no project-level way to say "this repo's analyse defaults to `advisory`."
2. **The analyse default contradicts the project's stated philosophy.** `analyse --fail-on` defaults to `error`, but the user's invariant for gating commands is "show everything and fail if anything is wrong" — i.e. `advisory`. Flipping the default is the natural counterpart to introducing the config dimension.
3. **gruff-py has no config schema version literal.** Sibling ports already version their schemas with `*.config.vN`. Introducing `gruff-py.config.v0.1` alongside this work avoids a separate disruptive cycle later.

The key name `minimumSeverity:` was selected after a structured wording brainstorm against the gruff-go draft (see linked critique). The shortlist evaluated `defaults.failOn` (rejected — vague container word; verb form clashes with `--fail-on` CLI flag), `severityThreshold:` (rejected — collides with the per-rule numeric `threshold` already used inside `rules.<id>` per ADR-014), `exitOn:` with ESLint vocabulary (rejected — would force a vocabulary migration off `advisory/warning/error`), `parameters.level:` PHPStan-style (rejected — alien to all five gruff-family configs), and flat per-command keys like `analyseSeverity:` (rejected — breaks the nesting convention used by `paths`, `selection`, `rules`). `minimumSeverity:` won on two axes: it matches the cross-port `minimum*` config-key idiom (`minimumPhpVersion` in `.gruff-php.yaml`, `minimumPythonVersion` in `.gruff-py.yaml`) and harmonises with gruff-go's `--min-severity` CLI flag name. gruff-py's own CLI flag remains `--fail-on`; the cross-port alignment is on the YAML/TOML key, not the flag.

The off-switch value `none` (rather than `never`) is the family-wide decision after the same brainstorm. gruff-py already exposes `FailThreshold.NONE` with string value `"none"`, so adopting it requires no source rename. gruff-go's current 0.1.2 draft ships `never`; the family decision is to flip gruff-go to `none` in a separate sibling-port workstream. The accept-set explicitly excludes `never` (and `off`, `disabled`, `medium`, `low`, `high`, `critical`, `info`, `notice`, `warn`) — no aliases.

Silent acceptance of non-gating keys was rejected because the failure mode is a CI footgun: a user adding `minimumSeverity.summary: advisory` would expect `summary` runs to gate but would silently get the existing non-gating behaviour, surfacing only when a CI run unexpectedly passed where it should have failed. A loud rejection at load time forces the user to confront the decision now, when it is cheap.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Top-level `minimumSeverity:` with `{analyse, report, dashboard}` accept-set, `none` off-switch, hard schema-version requirement | Pre-existing `.gruff-py.yaml` files break on load until `gruff-py init --force` runs. Validator must surface all key/value errors at once. CHANGELOG must call out the analyse default flip. | **Accepted.** Smallest persistent surface for the cross-port invariant; loud failure on schema-version absence is preferred over a back-compat shim that would have to be maintained indefinitely. |
| `defaults: { failOn: { analyse: advisory, ... } }` (verb-imperative inside a vague wrapper) | `defaults:` is a generic container word; `failOn:` clashes with the `--fail-on` CLI flag and overlaps the existing severity footgun. Two levels of nesting where one would do. | Rejected — convergent feedback from three independent critique passes; vague wrapper word, verb/flag collision. |
| `severityThreshold:` per-command map | "threshold" is already used inside the same file for per-rule numeric `threshold` (per ADR-014 single-severity rubrics); two meanings at different nesting depths invites confusion. | Rejected — vocabulary collision with ADR-014. |
| `exitOn:` with ESLint `warn/off` vocabulary | More semantically honest than "fail," but breaks the family-wide `advisory/warning/error` vocabulary; requires a value translator everywhere severity is read. | Rejected — wording-only brainstorm; vocabulary migration is out of scope and would lose sibling-port harmony. |
| Flat per-command keys (`analyseSeverity:`, `reportSeverity:`, `dashboardSeverity:`) | Breaks the local nesting convention (`paths`, `selection`, `rules` all use nested maps); adding a new gateable subcommand later would require a new top-level key instead of a new map entry. | Rejected — convention drift; nested map is the more extensible shape. |
| Silent-accept non-gating keys like `minimumSeverity.summary: advisory` | User expects gating on `summary`, gets the existing non-gating behaviour; the discrepancy surfaces only when CI behaves unexpectedly. | Rejected — explicit CI footgun. The validator rejects loudly with an error naming the offending key as non-gating and listing the accept-set. |
| Accept `never` as a synonym for `none` | Keeps gruff-go's existing wording usable in gruff-py too; back-compat for any user who saw the gruff-go 0.1.2 draft. | Rejected — the family-wide off-switch is `none`; aliases would freeze the divergence rather than resolve it. gruff-go is expected to flip to `none` before its 0.1.2 ships. |
| Skip the schema-version literal in 0.1.2 | Avoids breaking pre-existing config files now, at the cost of either (a) shipping the new key without versioning then bumping later (forces a second disruptive cycle) or (b) never versioning the config schema (drifts from sibling ports). | Rejected — sibling-port parity argues for introducing the version literal now, with a single break, rather than splitting the disruption across two releases. |
| Keep `analyse --fail-on` default at `error` | Preserves single-port back-compat but contradicts the stated "show everything and fail if anything is wrong" philosophy and forces every adopter to set `minimumSeverity.analyse: advisory` explicitly to get the intended default. | Rejected — cross-port invariant and stated project philosophy take priority over back-compat; CHANGELOG entry covers the migration. |

## Consequences

**Source:**

- `src/gruffpy/analysis/schema.py` grows one constant (`CONFIG_SCHEMA_VERSION = "gruff-py.config.v0.1"`); `src/gruffpy/analysis/__init__.py` re-exports it alongside `ANALYSIS_SCHEMA_VERSION`.
- `src/gruffpy/config/analysis_config.py::AnalysisConfig` grows a `minimum_severity: dict[str, FailThreshold]` field with a matching `with_minimum_severity` helper, mirroring the existing `with_*` pattern.
- `src/gruffpy/config/loader.py` extends `VALID_TOP_LEVEL_KEYS` with `{"schemaVersion", "minimumSeverity"}`, adds two validator helpers (`_validate_schema_version`, `_validate_minimum_severity`), and threads the resolved map through `_apply_config_section`.
- `src/gruffpy/cli_options.py` flips the `analyse --fail-on` decorator default from `"error"` to `"advisory"`; `report` and `dashboard` keep `"none"`.
- `src/gruffpy/cli.py` adds a `_fail_on_came_from_cli()` helper using `click.get_current_context().get_parameter_source("fail_on")`; the three command runners consult it before reading the config map and before falling back to the binary default.
- `src/gruffpy/command/init_config.py::render_default_config_yaml` emits the new `schemaVersion:` line and `minimumSeverity:` block at the top of every freshly rendered `.gruff-py.yaml`; the M03 follow-up wires preservation of a user-tuned block across `gruff-py init --force`.

**Tests:**

- Every non-rejection-asserting inline YAML/TOML fixture in `tests/unit/config/test_loader_precedence.py` and `tests/unit/command/test_init_config.py` gains a `schemaVersion:` line. Rejection-asserting fixtures stay as-is.
- New precedence tests cover: (a) config-set value with no flag, (b) config-set value with explicit flag (CLI wins), (c) no config + no flag (binary default), (d) unknown key (`summary`), (e) unknown value (`medium`), (f) rejected alias (`never`), (g) missing `schemaVersion:`, (h) wrong `schemaVersion:`.

**Docs (M03):**

- `docs/configuration.md`, `docs/ci-integration.md`, `docs/dashboard.md`, `docs/reporting.md`, `docs/output-formats.md`, and `README.md` reference the new key and the precedence rule. `CHANGELOG.md [Unreleased]` gets `Added` entries for the key and the schema-version literal, plus a `Changed` entry for the analyse default flip.
- A footgun entry records the cross-port lockstep: when the binary `--fail-on` default moves, the ADR, the renderer, the validator accept-set, the dashboard state factory, the docs block, and the CHANGELOG must all move with it.

**Cross-port:**

- gruff-go's draft 0.1.2 ADR currently uses `never`. Family-wide decision is `none`; the gruff-go plan is expected to flip before its 0.1.2 ships.
- gruff-rs, gruff-ts, gruff-php do not yet ship `minimumSeverity:`; adoption is a separate sibling-port workstream and not blocking for gruff-py 0.1.2.

## Reversibility

**One-way door on the schema-version literal.** Once `gruff-py.config.v0.1` is declared and pre-0.1.2 configs are rejected on load, downgrading to a no-version policy would require a coordinated cross-port reversal. Bumping the literal forward (e.g. `v0.2`) is a normal two-way move within the schema-version contract.

**Two-way door on the key name and accept-sets.** Adding a new gateable subcommand later means adding it to the validator's key accept-set and giving it a `--fail-on` decorator. Removing one means removing it from both. Adding a new severity value requires a coordinated change to `FailThreshold` and every sibling port's enum — it is two-way but cross-port-coordinated, not unilateral.

**Two-way door on the analyse default flip.** Reverting `analyse` to `error` is one CHANGELOG entry and one decorator-default edit, but undoes the rationale recorded in this ADR; do not flip back without re-opening the philosophy decision.

**Revisit triggers:**

- A future external user reports that `advisory` as the lowest-but-still-CI-blocking tier is semantically jarring (open question deferred from the wording brainstorm). The fix is either a wording change at the value level or a doc-level glossary entry; the key-level decisions here stand regardless.
- gruff-go ships its 0.1.2 with `never` rather than flipping to `none`. The family-wide invariant breaks; either gruff-py reverts to `never` (rejected here for the no-alias reason) or gruff-go must follow.
- A new subcommand becomes gateable. The accept-set grows; this ADR's structure stands.
