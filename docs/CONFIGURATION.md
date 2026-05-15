# Configuration

gruff-py works without a config file. Configuration is only needed when you
want to ignore paths, select rules, adjust thresholds, or allow known safe
terms.

## Precedence

The first matching source wins:

1. `gruff analyse --config <path>`
2. `.gruff.yaml` in the project root
3. `[tool.gruff]` in `pyproject.toml`
4. Built-in defaults from `RuleRegistry.defaults()`

Use `--no-config` to skip all config files.

## YAML Example

```yaml
minimumPythonVersion: "3.11"

paths:
  ignore:
    - "tests/fixtures/**"
    - "generated/**"

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
    thresholds:
      warning: 500
      error: 900

  test-quality.testdox-readability:
    enabled: true
```

## pyproject.toml Example

```toml
[tool.gruff]
minimumPythonVersion = "3.11"

[tool.gruff.paths]
ignore = ["tests/fixtures/**", "generated/**"]

[tool.gruff.allowlists]
acceptedAbbreviations = ["API", "URL"]
secretPreviews = ["example-token-prefix"]

[tool.gruff.selection]
excludeRules = ["docs.missing-module-docstring"]

[tool.gruff.rules."size.file-length"]
thresholds = { warning = 500, error = 900 }

[tool.gruff.rules."test-quality.testdox-readability"]
enabled = true
```

## Supported Keys

Top-level keys:

| Key | Type | Meaning |
|---|---|---|
| `minimumPythonVersion` | string | Minimum Python version, currently at least `3.11` |
| `paths` | table | Path ignore configuration |
| `allowlists` | table | Naming and secret-preview allowlists |
| `selection` | table | Rule and pillar selection |
| `rules` | table | Per-rule settings |

`paths`:

| Key | Type | Meaning |
|---|---|---|
| `ignore` | list of strings | Project-relative ignore patterns |

`allowlists`:

| Key | Type | Meaning |
|---|---|---|
| `acceptedAbbreviations` | list of strings | Abbreviations accepted by naming rules |
| `secretPreviews` | list of strings | Known safe secret previews |

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
| `thresholds` | table | Numeric threshold overrides |
| `options` | table | Rule-specific options |

Unknown keys are rejected with a `config-error` diagnostic and exit code `2`.

## Ignored Paths

gruff-py skips dependency, build, cache, generated, and VCS directories by
default, including `.git`, `.venv`, `node_modules`, `vendor`, `dist`, `build`,
`htmlcov`, `__pycache__`, and common tool caches.

It also skips lockfiles that commonly contain high-entropy hashes, such as
`uv.lock`, `poetry.lock`, `package-lock.json`, `composer.lock`, `Cargo.lock`,
and `go.sum`.

Use `--include-ignored` when you intentionally want to scan those paths.

## Display Filters Are Not Config Selection

CLI options such as `--min-severity`, `--include-pillar`, and `--exclude-rule`
filter what gets rendered. They do not change scoring or the `--fail-on` exit
calculation.

Use config `selection` when you want to change which rules run.

