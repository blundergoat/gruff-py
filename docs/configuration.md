# Configuration

gruff-py works without a config file. Configuration is only needed when you
want to ignore paths, select rules, adjust thresholds, or allow known safe
terms.

## Generating a default `.gruff-py.yaml`

Run `gruff-py init` to write a default `.gruff-py.yaml` in the current
directory. The generated file mirrors `RuleRegistry.defaults()`: every
built-in rule with its default `enabled`, `thresholds`, and `options`,
plus starter `paths.ignore` entries for local agent/tooling directories and
test fixtures. Allowlists and selection lists are empty. Re-run with `--force`
to regenerate an existing file while preserving its `paths.ignore` entries.

The generated file also notes that built-in ignored paths and `.gitignore`
already apply before `paths.ignore`. After reviewing a first scan, run
`gruff-py analyse . --generate-baseline --fail-on none` if you want future
runs to treat current findings as known debt.

## Precedence

The first matching source wins:

1. `gruff-py analyse --config <path>`
2. `.gruff-py.yaml` in the project root
3. `[tool.gruff-py]` in `pyproject.toml`
4. Built-in defaults from `RuleRegistry.defaults()`

Use `--no-config` to skip all config files.

## YAML Example

```yaml
schemaVersion: gruff-py.config.v0.1

minimumSeverity:
  analyse: advisory
  report: none
  dashboard: none

minimumPythonVersion: "3.11"

paths:
  ignore:
    - ".agents/"
    - ".antigravitycli/"
    - ".claude/"
    - ".codex/"
    - ".github/"
    - ".goat-flow/"
    - "tests/fixtures/**"

allowlists:
  acceptedAbbreviations:
    - API
    - URL
  secretPreviews:
    - "example-token-prefix"

selection:
  excludeRules:
    - docs.missing-module-docstring

rules:
  size.file-length:
    threshold: 900
    severity: error

  test-quality.eager-test:
    thresholds:
      maxAssertions: 5

  naming.boolean-prefix:
    options:
      acceptedBooleanNames:
        - ok
        - enabled
        - verbose
```

## pyproject.toml Example

```toml
[tool.gruff-py]
schemaVersion = "gruff-py.config.v0.1"
minimumPythonVersion = "3.11"

[tool.gruff-py.minimumSeverity]
analyse = "advisory"
report = "none"
dashboard = "none"

[tool.gruff-py.paths]
ignore = [
    ".agents/",
    ".antigravitycli/",
    ".claude/",
    ".codex/",
    ".github/",
    ".goat-flow/",
    "tests/fixtures/**",
]

[tool.gruff-py.allowlists]
acceptedAbbreviations = ["API", "URL"]
secretPreviews = ["example-token-prefix"]

[tool.gruff-py.selection]
excludeRules = ["docs.missing-module-docstring"]

[tool.gruff-py.rules."size.file-length"]
threshold = 900
severity = "error"

[tool.gruff-py.rules."test-quality.eager-test"]
thresholds = { maxAssertions = 5 }

[tool.gruff-py.rules."naming.boolean-prefix".options]
acceptedBooleanNames = ["ok", "enabled", "verbose"]
```

## Supported Keys

Top-level keys:

| Key | Type | Meaning |
|---|---|---|
| `schemaVersion` | string | Config schema literal; must equal `gruff-py.config.v0.1` |
| `minimumSeverity` | table | Per-command `--fail-on` defaults (see [Severity Gate](#severity-gate)) |
| `minimumPythonVersion` | string | Minimum Python version, currently at least `3.11` |
| `paths` | table | Path ignore configuration |
| `allowlists` | table | Naming and secret-preview allowlists |
| `selection` | table | Rule and pillar selection |
| `rules` | table | Per-rule settings |
| `outputVolumeHintThreshold` | integer | Finding count at which `analyse --format text` appends a pointer to `summary --group-by=rule` (default `50`; `0` disables) |

`minimumSeverity`:

| Key | Type | Meaning |
|---|---|---|
| `analyse` | string | Default `--fail-on` for `gruff-py analyse` (one of `advisory`, `warning`, `error`, `none`) |
| `report` | string | Default `--fail-on` for `gruff-py report` |
| `dashboard` | string | Default `--fail-on` seeded into the dashboard form |

Keys for non-gating subcommands (`summary`, `list-rules`, `metric-calibration`, `init`, `list`, `help`, `completion`) are rejected by the loader.

`paths`:

| Key | Type | Meaning |
|---|---|---|
| `ignore` | list of strings | Project-relative ignore patterns |

`allowlists`:

| Key | Type | Meaning |
|---|---|---|
| `acceptedAbbreviations` | list of strings | Abbreviations accepted by naming rules |
| `secretPreviews` | list of strings | Known safe secret previews |
| `deadCode` | table | Dead-code allowlist with `symbols`, `decorators`, and `paths` keys (each a list of strings) that suppress dead-code findings |

`selection`:

| Key | Type | Meaning |
|---|---|---|
| `tiers` | list of strings | Include selected rule tiers |
| `pillars` | list of strings | Include selected pillars |
| `rules` | list of strings | Include selected rule ids |
| `excludePillars` | list of strings | Exclude selected pillars |
| `excludeRules` | list of strings | Exclude selected rule ids |

Per-rule settings:

| Key | Type | Meaning |
|---|---|---|
| `enabled` | bool | Enable or disable the rule |
| `threshold` | number | Single numeric threshold for rules with warning/error metric defaults |
| `severity` | string | Finding severity for `threshold`: `warning` or `error` |
| `thresholds` | table | Named numeric threshold knobs, such as `maxAssertions` or `entropy` |
| `options` | table | Rule-specific options |

Use `threshold` plus `severity` for metric rules that have warning/error
defaults. Keep `thresholds` for named tuning values. Do not combine
`threshold` and `thresholds` in the same rule entry.

Unknown keys are rejected: the default text output prints an error to stderr and exits `1`, while `--format json` emits a `config-error` diagnostic object and exits `2`.

## Boolean Boundary Names

`naming.boolean-prefix` normally asks boolean-returning functions, methods, and
fields to use names such as `is_ready`, `has_token`, or `can_retry`. Exact
external boundary names can be allowed with
`rules.naming.boolean-prefix.options.acceptedBooleanNames` when a rename would
break a CLI option, DTO/schema field, wire-format key, or protocol contract.

Before configuring an exact boundary name, `ok` is treated like any other vague
boolean name:

```python
def ok() -> bool:
    return True
```

After adding an exact allowlist entry, the protocol name can remain stable
without disabling the rule for unrelated names:

```yaml
rules:
  naming.boolean-prefix:
    options:
      acceptedBooleanNames:
        - ok
```

Prefer the narrowest exact names needed by the boundary. Do not add broad
project vocabulary when the identifier can be renamed to a clearer boolean
prefix.

## Severity Gate

`minimumSeverity` sets per-command defaults for the `--fail-on` flag. The
resolved threshold is the first match of:

1. `--fail-on <value>` passed on the command line.
2. `minimumSeverity.<command>` from the loaded config.
3. The built-in default for that subcommand (`analyse: advisory`; `report` and
   `dashboard`: `none`).

The accepted values are `advisory`, `warning`, `error`, and `none` — no
aliases. The off-switch value is `none`. Use `none` to publish reports
without failing the run.

Keys must be the gateable subcommand names (`analyse`, `report`, `dashboard`).
Adding `summary: advisory` or any other key is a hard error; silent acceptance
would be a CI footgun.

See [ADR-019](../.goat-flow/decisions/ADR-019-per-command-minimum-severity.md)
for the rationale, the rejected alternatives, and the cross-port invariant.

## Schema Version

`schemaVersion: gruff-py.config.v0.1` is required at the top of every
`.gruff-py.yaml` and `[tool.gruff-py]` block. Configs without it (including
pre-0.1.2 files) are rejected on load. Regenerate with:

```bash
gruff-py init --force
```

`init --force` preserves a user-tuned `paths.ignore` list and a user-tuned
`minimumSeverity:` block; both survive byte-for-byte across regeneration.

## Ignored Paths

Source discovery applies three layers of exclusions, in order:

1. **Default-ignored directories.** gruff-py skips dependency, build, cache,
   generated, and VCS directories: `.git`, `.venv`, `node_modules`, `vendor`,
   `dist`, `build`, `htmlcov`, `__pycache__`, and common tool caches. It also
   skips lockfiles that commonly contain high-entropy hashes, such as
   `uv.lock`, `poetry.lock`, `package-lock.json`, `composer.lock`,
   `Cargo.lock`, and `go.sum`.
2. **`.gitignore` exclusions.** Any path the project's `.gitignore` files
   (root plus nested) exclude is skipped by default. Nested `.gitignore`
   files override their parents; negation patterns (`!keep.py`) are honored.
   `.git/info/exclude` and the user's global gitignore are not consulted.
3. **Configured `paths.ignore` patterns.** Project-relative globs declared
   in your config layer on top of the previous two.

`--include-ignored` bypasses layers 1 and 2 (default-ignored directories
**and** `.gitignore`). It does not bypass layer 3 - `paths.ignore` is your
explicit, intentional exclusion list and remains active.

Projects without a `.gitignore` are scanned as before.

## Baselines

Baselines are for incremental adoption on existing projects. After reviewing
the current findings, generate a baseline:

```bash
gruff-py analyse . --generate-baseline --fail-on none
```

This writes `gruff-baseline.json` using `gruff-py.baseline.v1` and leaves the
current run's findings visible. Future `analyse` and `report` runs apply that
default baseline automatically, suppressing findings whose fingerprint, rule
id, and file still match. Use `--baseline-path <path>` for an explicit baseline,
or `--no-baseline` to audit without any baseline.

Generate and apply baselines with the same paths, config, and ignore flags you
plan to use in CI; the baseline only records findings from the files scanned in
that run.

## Display Filters Are Not Config Selection

CLI options such as `--min-severity`, `--include-pillar`, and `--exclude-rule`
filter what gets rendered. They do not change scoring or the `--fail-on` exit
calculation.

Use config `selection` when you want to change which rules run.
