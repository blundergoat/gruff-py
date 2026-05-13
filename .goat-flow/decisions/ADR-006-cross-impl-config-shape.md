# ADR-006: Cross-impl config shape and file precedence

**Status:** Accepted
**Date:** 2026-05-13
**Ticket/Context:** `.goat-flow/tasks/0.1/M02.5-gruff-yaml-config-v0.1.md`; cross-impl parity with gruff-php and gruff-ts, both of which use `.gruff.yaml` as their primary config surface.

## Decision

gruff-py supports configuration from **two file formats**:

1. `.gruff.yaml` at the project root.
2. `[tool.gruff]` block in `pyproject.toml` at the project root.

The two formats share **the same option-key shape** wherever they apply. Concretely:

| Concept | TOML key (existing) | YAML key (new) |
|---|---|---|
| Minimum Python version | `[tool.gruff] minimumPythonVersion` | `minimumPythonVersion` (top-level) |
| Path ignore globs | `[tool.gruff.paths] ignore = [...]` | `paths.ignore: [...]` |
| Accepted abbreviations | `[tool.gruff.allowlists] acceptedAbbreviations = [...]` | `allowlists.acceptedAbbreviations: [...]` |
| Allowed secret previews | `[tool.gruff.allowlists] secretPreviews = [...]` | `allowlists.secretPreviews: [...]` |
| Rule selection | `[tool.gruff.selection] tiers/pillars/rules/excludePillars/excludeRules` | `selection.<same>: [...]` |
| Per-rule settings | `[tool.gruff.rules."<id>"] enabled / thresholds / options` | `rules.<id>.enabled / thresholds / options` |

Cross-impl users (gruff-php / gruff-ts) can copy the same `.gruff.yaml` between repos; only Python-specific values diverge (e.g. ignored directory patterns for `__pycache__`, `.venv` are Python-native).

## File precedence

When loading, gruff-py uses this priority order, picking the **first** that exists:

1. **CLI `--config <path>`** — explicit, format auto-detected by extension (`.yaml`/`.yml` → YAML; `.toml` → TOML; anything else → TOML for legacy).
2. **`.gruff.yaml`** at the project root.
3. **`pyproject.toml`** `[tool.gruff]` at the project root.
4. **Built-in defaults** from `RuleRegistry.defaults()`.

The loaded source is reported in `AnalysisReport.config_path` so `gruff analyse --format json` makes the choice user-visible.

## Context

gruff-php and gruff-ts ship with `.gruff.yaml` as the canonical config. Python users dropping into a gruff-managed repo and finding only `[tool.gruff]` in `pyproject.toml` (or vice versa) is friction every gruff-cross-impl user hits. Adding `.gruff.yaml` support while keeping `pyproject.toml` support keeps Python idioms working for users who prefer them, and matches the cross-impl muscle memory for everyone else.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| **Both `.gruff.yaml` and `pyproject.toml` supported, YAML wins** (accepted) | Adds a runtime dep (`pyyaml`); users surprised by precedence may misconfigure. | Accepted: cross-impl ergonomic parity + Python idiom preserved. Surface the loaded source in `gruff analyse` to mitigate precedence surprise. |
| `.gruff.yaml` only — drop pyproject.toml support | Strictest cross-impl parity, but breaks existing dogfood config in `pyproject.toml`; forces every Python user into a new file. | Rejected: migration cost outweighs parity gain. |
| `pyproject.toml` only — never accept YAML | Closest to Python convention. | Rejected: doesn't solve the cross-impl-ergonomic problem the user surfaced. |
| Different YAML keys than gruff-php (Python-native names) | Easier for Python users; harder for cross-impl users. | Rejected: same option names is the load-bearing parity benefit. |

## Consequences

- `pyyaml>=6.0` becomes a runtime dependency (~500KB install). `safe_load` only — no arbitrary tag construction. Crosses the Ask First boundary in `CLAUDE.md` for `pyproject.toml` dependency edits.
- `[tool.gruff.rules]` in TOML uses keys like `"size.file-length"` (quoted because of the dot). In YAML, the same key is `rules.size.file-length` (unquoted; dots in YAML keys are legal). Both forms produce the same `AnalysisConfig` shape.
- Cross-impl JSON byte-equivalence (per `.goat-flow/footguns/compatibility.md`) is unaffected — config affects WHICH rules run, not the JSON shape they emit.

## Reversibility

**Two-way door for the format choice.** Removing `.gruff.yaml` support is a single-PR change (drop the loader + dep). Removing `[tool.gruff]` support would break existing users; gruff-py treats it as the long-term primary path.

Revisit triggers:
- gruff-php / gruff-ts switch their config format → coordinate.
- `pyyaml` security incident → consider `ruamel.yaml` or a minimal hand-rolled parser.
