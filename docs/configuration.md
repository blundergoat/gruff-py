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

deepScanBudget:
  enabled: true
  maxLines: 20000
  maxBytes: 2000000

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

selection:
  excludeRules:
    - docs.missing-module-docstring

sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: tests/fixtures/aws-sample.env
    reason: Synthetic key used by the loader fixture; not a live credential.

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

[tool.gruff-py.deepScanBudget]
enabled = true
maxLines = 20000
maxBytes = 2000000

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

[tool.gruff-py.selection]
excludeRules = ["docs.missing-module-docstring"]

[[tool.gruff-py.sensitiveExclusions]]
rule = "sensitive-data.aws-access-key"
path = "tests/fixtures/aws-sample.env"
reason = "Synthetic key used by the loader fixture; not a live credential."

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
| `deepScanBudget` | table | Paired line/byte limits for deep Python analysis; either exceeded bound degrades the file |
| `paths` | table | Path ignore configuration |
| `allowlists` | table | Naming and secret-preview allowlists |
| `selection` | table | Rule and pillar selection |
| `sensitiveExclusions` | list of tables | Reviewed scopes where one sensitive-data rule stays quiet (see [Sensitive Data Exclusions](#sensitive-data-exclusions)) |
| `rules` | table | Per-rule settings |
| `outputVolumeHintThreshold` | integer | Finding count at which `analyse --format text` appends a pointer to `summary --group-by=rule` (default `50`; `0` disables) |

`minimumSeverity`:

| Key | Type | Meaning |
|---|---|---|
| `analyse` | string | Default `--fail-on` for `gruff-py analyse` (one of `advisory`, `warning`, `error`, `none`) |
| `report` | string | Default `--fail-on` for `gruff-py report` |
| `dashboard` | string | Default `--fail-on` seeded into the dashboard form |

Keys for non-gating subcommands (`summary`, `list-rules`, `metric-calibration`, `init`, `list`, `help`, `completion`) are rejected by the loader.

`deepScanBudget`:

| Key | Type | Meaning |
|---|---|---|
| `enabled` | boolean | Enables the budget (default `true`); set false to disable it |
| `maxLines` | positive integer | Maximum physical source lines before degradation (default `20000`) |
| `maxBytes` | positive integer | Maximum source bytes before degradation (default `2000000`) |

The budget applies only after `.py` source classification. Exceeding either
bound keeps the file analysed and continues raw-text size, sensitive-data, and
configuration checks, but omits masking, suppression-directive parsing, AST
walking, and other deep Python analysis. A non-fatal `bounded-deep-scan`
diagnostic names the path, both measured counts, both effective limits, and
whether they came from `default`, `config`, or `cli`. Use
`--deep-scan-budget LINES:BYTES` on `analyse`, `report`, `summary`, `dashboard`,
or `hook` to atomically override both limits; `--deep-scan-budget off` disables
the guard. The CLI value wins over config.

`paths`:

| Key | Type | Meaning |
|---|---|---|
| `ignore` | list of strings | Project-relative ignore patterns |

`allowlists`:

| Key | Type | Meaning |
|---|---|---|
| `acceptedAbbreviations` | list of strings | Complete abbreviation list accepted by naming rules; a configured list replaces, rather than extends, the family seed |
| `secretPreviews` | list of strings | **Retired.** Only an empty list is still accepted. A non-empty value is a fatal configuration error: a secret preview never suppressed a finding safely, because the suppression key was derived from the matched value itself. Use `sensitiveExclusions` instead, which names an exact rule and path and requires a written reason. |
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

Unknown top-level keys and structural configuration errors are rejected: the
default text output prints an error to stderr and exits `1`, while
`--format json` emits a `config-error` diagnostic object and exits `2`.
Unknown rule IDs and per-rule keys follow the warning policy in
[Unknown Rule And Option Keys](#unknown-rule-and-option-keys-warn-by-default---strict-config-to-fail).

## Sensitive Data Exclusions

`sensitiveExclusions` is the only configuration that silences a `sensitive-data.*` finding. It is
deliberately separate from `selection`, so no message- or value-matching key can ever apply to the
sensitive-data pillar.

```yaml
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: tests/fixtures/aws-sample.env
    symbol: Fixtures.aws_sample          # optional
    reason: Synthetic key used by the loader fixture; not a live credential.
```

```toml
[[tool.gruff-py.sensitiveExclusions]]
rule = "sensitive-data.aws-access-key"
path = "tests/fixtures/aws-sample.env"
reason = "Synthetic key used by the loader fixture; not a live credential."
```

You write every entry by hand. No preview, message excerpt, or matched value is ever turned into
an entry automatically, and no `analyse` flag generates this section.

| Key | Type | Meaning |
|---|---|---|
| `rule` | string | Exactly one rule id, inside the sensitive-data pillar |
| `path` | string | Exactly one project-relative path, as findings report it |
| `symbol` | string | Optional qualified symbol that narrows the scope further |
| `reason` | string | Non-empty rationale a reviewer can judge |

A finding is suppressed only when its rule id, its project-relative path, and - when the entry
names one - its symbol all match exactly. The same rule in another file and another rule in the
same file both keep reporting. No sensitive-data rule stamps a symbol today, so an entry carrying
`symbol` correctly matches nothing.

An entry that matches nothing is not an error. It reports `suppressed: 0`, so removing the
underlying secret never breaks a build.

Every one of these is a fatal configuration error naming the entry index and the key to fix:

- `rule` missing, empty, or carrying a wildcard, glob, or regular-expression metacharacter;
- `rule` naming a pillar or tier selector rather than one exact rule id;
- `rule` naming an unknown rule id, or a known rule id outside the sensitive-data pillar;
- `path` missing, empty, absolute, containing `..`, or carrying a glob metacharacter;
- any key outside `rule`, `path`, `symbol`, and `reason` - `message_contains`, `value`, and
  `preview` included;
- `reason` missing, empty, or whitespace-only;
- a second entry with the same `rule`, `path`, and `symbol`, because two entries claiming one
  scope would split the audit count.

A suppressed finding leaves the score and the exit code exactly as an inline `# gruff: disable=`
directive does, and it is never invisible. Every entry publishes one row in the report's
`suppressions` array:

```json
{"index": 0, "rule": "sensitive-data.aws-access-key", "paths": ["tests/fixtures/aws-sample.env"],
 "symbol": null, "reason": "Synthetic key used by the loader fixture; not a live credential.",
 "suppressed": 2}
```

`analyse --format text` and `summary` print the same total under a `Sensitive exclusions` heading;
`summary --format json` filters without publishing a count until `gruff.summary.v2` gains a
suppression surface. No reported
field carries matched value material: `reason` and `path` come from your configuration, and nothing
in the audit row is derived from the value a rule matched.

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

Source discovery applies four layers of exclusions, in order:

1. **Configured `paths.ignore` patterns.** Project-relative globs are
   authoritative for directory walks, explicit file operands, and changed-region
   scans.
2. **VCS internals.** `.git`, `.hg`, and `.svn` are always blocked, including
   with `--include-ignored` or an explicit file operand.
3. **`.gitignore` exclusions.** Any path the project's `.gitignore` files
   (root plus nested) exclude is skipped by default. Nested `.gitignore`
   files override their parents; negation patterns (`!keep.py`) are honored.
   `.git/info/exclude` and the user's global gitignore are not consulted.
4. **No-gitignore fallback.** When no `.gitignore` exists from the project root
   through a candidate's parent, gruff-py skips `.fleet`, `.idea`, `.vscode`,
   `build`, `coverage`, `dist`, `node_modules`, and `vendor`, plus Python's
   `.mypy_cache`, `.pyre`, `.pytest_cache`, `.pytype`, `.ruff_cache`, `.tox`,
   `.venv`, `__pycache__`, `htmlcov`, and `venv` exceptions, at any depth.

`--include-ignored` bypasses layers 3 and 4 only. An explicit supported file
also bypasses those two layers. Lockfile names do not exclude a file: eligible
forms such as `package-lock.json` are scanned, while `.lock` files remain outside
the existing extension set.

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
