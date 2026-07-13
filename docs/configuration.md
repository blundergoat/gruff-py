# Configuration

gruff-py works without a config file. Configuration is only needed when you
want to ignore paths, select rules, adjust thresholds, or allow known safe
terms.

## Generating a default `.gruff-py.yaml`

Run `gruff-py init` to write a default `.gruff-py.yaml` in the current
directory. The generated file mirrors `RuleRegistry.defaults()`: every
built-in rule with its default `enabled`, `thresholds`, and `options`,
plus starter `paths.ignore` entries for local agent/tooling directories and
test fixtures. It also includes the family abbreviation seed; other allowlists
and selection lists are empty.

Re-run with `--force` only to canonically regenerate a valid existing
`.gruff-py.yaml`. Every supported loaded setting is preserved, but comments,
key order, and formatting may change. The command fails closed and leaves files
unchanged when the target is malformed or when discovery finds `.gruff.yaml`
or a `pyproject.toml` table instead. Convert legacy YAML with
`gruff-py migrate-config`; edit `[tool.gruff-py]` TOML by hand.

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
| `acceptedAbbreviations` | list of strings | Complete abbreviation list accepted by naming rules; a configured list replaces, rather than extends, the family seed |
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

## Accepted Abbreviation Vocabulary

`naming.abbreviation` treats tokens such as `ctx`, `cfg`, `req`, and `idx` as
unclear until the project documents them. When one of those tokens has one
established domain meaning, add it to `allowlists.acceptedAbbreviations` rather
than suppressing each finding.

The configured list replaces the universal seed; it does not extend it. Start
from the visible list produced by `gruff-py init`, retain the seed entries the
project uses, and append reviewed project vocabulary. Configuring only `ctx`
would also remove seed entries such as `id`, `url`, and `db` from the resolved
allowlist.

Prefer a rename when the short token is temporary, ambiguous, or means
different things in different modules. The allowlist is a project vocabulary
contract, not a general exemption for short names.

## Boolean Boundary Names

`naming.boolean-prefix` normally asks boolean-returning functions, methods, and
fields to use names such as `is_ready`, `has_token`, or `can_retry`. Exact
external boundary names can be allowed with
`rules.naming.boolean-prefix.options.acceptedBooleanNames` when a rename would
break a CLI option, DTO/schema field, wire-format key, or protocol contract.

The rule matches scalar annotation shapes only: `bool`, exact optional forms
such as `Optional[bool]`, `bool | None`, and `Union[bool, None]`, plus
`Annotated` wrappers around those shapes. It does not treat `list[bool]`,
`tuple[bool, ...]`, dictionaries, iterators, generators, callables, mixed
unions, or arbitrary generics as scalar Boolean declarations. Explicit quoted
annotations use the same bounded syntax matcher; gruff-py never evaluates the
text or imports user code.

Emitted findings add provisional `metadata.annotationShape` with `bool`,
`optional-bool`, or `annotated-bool` so report consumers can explain why the
name was reviewed. This additive key is registered in workspace
`FAMILY-CONTRACT.md` §4 pending family vocabulary ratification; it does not
participate in fingerprints or stable identities.

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

## Tooling And Evaluation Paths

gruff-py does not currently support path-scoped rule or severity overlays in a
single config. `paths.ignore` is not a structural-noise control: it removes the
matched files from every rule, including security and sensitive-data checks.

For a tooling or evaluation tree that needs a lower structural bar, use
explicit config files and separate runs. Explicit filenames such as
`.gruff-py-tooling.yaml` are loaded only when passed with `--config`, so they do
not change the normal project scan.

For example, a reviewed guidance-only tooling config can relax selected
structural rules:

```yaml
schemaVersion: gruff-py.config.v0.1
rules:
  naming.boolean-prefix:
    enabled: false
  complexity.cognitive:
    threshold: 30
    severity: warning
```

A separate safety config keeps the same tooling path gated without running the
structural catalogue:

```yaml
schemaVersion: gruff-py.config.v0.1
selection:
  pillars:
    - security
    - sensitive-data
```

Run production, tooling guidance, and tooling safety as distinct checks:

```bash
gruff-py analyse src/ --config .gruff-py.yaml
gruff-py analyse tools/ --config .gruff-py-tooling.yaml --fail-on none
gruff-py analyse tools/ --config .gruff-py-tooling-security.yaml --fail-on advisory
```

The guidance run still renders structural findings but does not fail. The
safety run gates every finding from the selected safety pillars. Calibrate the
tooling config against the real scripts rather than copying the example
threshold as a universal recommendation.

For one isolated file contract, a precise file directive is smaller than a
second config:

```python
# gruff: disable-file=naming.boolean-prefix -- external evaluation schema fixes these names
```

Keep the rationale local and suppress only the named rule. See
[Suppressing Findings](rules.md#suppressing-findings) for the complete syntax.

## Markdown Link Sanitizers

`security.unsanitized-markdown-interpolation` checks visible labels and click
targets separately. In 0.5.0, labels trust no call by default. URLs trust
`urllib.parse.quote` and `urllib.parse.quote_plus` only when no `safe` argument
is supplied, or when `safe` is a literal string containing none of `]`, `(`,
or `)`. A dynamic `safe`, `safe='()'`, a second positional value containing
those delimiters, or any `*args`/`**kwargs` splat remains a finding.

Configure project helpers by their exact Python call targets:

```yaml
rules:
  security.unsanitized-markdown-interpolation:
    options:
      labelSanitizers:
        - markdown_label
        - helpers.markdown_label
      urlSanitizers:
        - urllib.parse.quote
        - urllib.parse.quote_plus
        - helpers.markdown_url
```

Targets are exact dotted identifiers: no wildcards, substrings, or inferred
`safe`/`escape` names. Same-file imports are recognized, so
`from urllib.parse import quote as encode_url` lets `encode_url(value)` match
the canonical URL default until that alias is reassigned or shadowed by a
parameter. The scanner never imports user code or follows an import graph.

Set either list to `[]` for strict mode in that slot. In particular,
`urlSanitizers: []` makes even `urllib.parse.quote(...)` untrusted. An empty
`labelSanitizers` list is already the generated default.

`html.escape` and `markupsafe.escape` are not label defaults. Both leave the
Markdown delimiters `]`, `(`, and `)` unchanged, so a label such as
`evil](https://bad.example)` still injects a rival link. Add one to
`labelSanitizers` only after verifying that the project's renderer makes HTML
escaping sufficient for that specific context.

Migration from 0.4.1: the old rule accepted any wrapper call. Add every real
project sanitizer to the matching option, then review findings from `str(...)`,
identity helpers, wrong-slot calls, shadowed targets, raw overwrites, and
ambiguous branches. Assigned sanitizer results and one-hop value aliases remain
accepted within the same function.

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

See [ADR-019](../.goat-flow/learning-loop/decisions/ADR-019-per-command-minimum-severity.md)
for the rationale, the rejected alternatives, and the cross-port invariant.

## Schema Version

`schemaVersion: gruff-py.config.v0.1` is required at the top of every
`.gruff-py.yaml` and `[tool.gruff-py]` block. Configs without it (including
pre-0.1.2 files) are rejected on load. For legacy YAML, preview and apply the
supported migration with:

```bash
gruff-py migrate-config --dry-run
gruff-py migrate-config
```

For `[tool.gruff-py]` in `pyproject.toml`, update `schemaVersion` by hand;
`migrate-config` does not rewrite TOML. `init --force` is not a schema-recovery
or source-conversion command: it accepts only a valid `.gruff-py.yaml` target.

## Unknown Rule And Option Keys: Warn By Default, `--strict-config` To Fail

Unknown rule-level config keys downgrade to warnings instead of aborting the
run: an unknown rule id, an unknown key inside a rule section, an unknown
`thresholds.<name>` knob (including the legacy two-tier `warning`/`error`
shape), a `threshold` on a rule without a severity rubric, or a `severity`
without a `threshold`. An unknown `options.<name>` key follows the same path.
The accepted option names come only from that rule's registered defaults; a
rule with no default options accepts no configured option names.

For example, this misspells `allow_bullets` while also setting the valid
`min_fields` sibling:

```yaml
rules:
  docs.dataclass-attributes:
    options:
      min_fields: 6
      allowBullet: false
```

A normal scan warns with the exact dotted key
`rules.docs.dataclass-attributes.options.allowBullet`, removes only that key,
applies `min_fields`, and keeps the registered `allow_bullets` default. The
warning is echoed to stderr, rendered in the text report's `Config warnings`
block, and serialized in the additive `run.configWarnings` JSON array. Config
warnings never change the finding-driven exit code.

Pass `--strict-config` (on `analyse`, `report`, and `summary`) to turn those
shapes into hard failures. The same example then stops at the full dotted key
and lists the registered alternatives without claiming the typo was ignored.
This is useful for CI jobs that must not run with a half-applied config.
Structural errors - non-table sections, wrong value types, unknown top-level
keys, and `schemaVersion` mismatches - always fail regardless of the flag.

The loader has no generic option type schema. Once a name is registered, its
consuming rule owns value and cross-option constraints. A rule may surface
those constraints as config errors before analysis; for example, the Markdown
sanitizer options require lists of exact Python call targets and reject empty
strings, wildcards, and non-text entries.

## Migrating Legacy Configs: `gruff-py migrate-config`

`gruff-py migrate-config` rewrites known legacy key shapes in the discovered
YAML config (`.gruff-py.yaml` or `.gruff.yaml`; `--config <path>` selects an
explicit file):

- `rules.<id>.thresholds: {warning, error}` becomes a single `threshold` plus
  `severity`. When both tiers are present the error tier wins (the warning
  tier is dropped, honouring the single-threshold contract); a warning-only
  tier maps to `severity: warning`.
- A missing or stale `schemaVersion` is pinned to the current value.
- `paths.ignore`, `allowlists`, `selection`, `minimumSeverity`, per-rule
  `enabled` and `options` (including `conventionalModuleNames`), and valid
  `thresholds` knobs pass through unchanged.

The command prints one line per change plus a unified diff; `--dry-run`
prints without writing. YAML comments are not preserved when a rewrite
happens - review the diff before committing. `pyproject.toml`
`[tool.gruff-py]` blocks are not rewritten; the command prints the equivalent
hand-edit instructions instead.

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
