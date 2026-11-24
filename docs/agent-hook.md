# Using gruff-py As A Coding-Agent Hook

gruff-py is built to govern code produced by a coding agent before a human
reviewer is asked to sign off on it. In that loop, the useful gate is the
agent's changed code, not every historical finding in the repository.

## Preferred Hook Contract

Use `hook` when an editor or coding-agent PostToolUse hook wants one stable JSON
shape without per-analyzer logic:

```sh
uv run gruff-py hook src/foo.py \
  --format json \
  --changed-ranges "12-40,88-90"
```

`hook` emits `contractVersion: "gruff.hook.v2"`. Because the hook's own
`--fail-on` defaults to `none`, findings stay advisory unless the caller opts
into a gate:

- **Exit `0`** — analysis completed and nothing reached the requested gate.
- **Exit `1`** — an explicit gate tripped: `--fail-on <severity>` (at or above
  that severity and `--min-confidence`), `--fail-on-new` (any published finding
  classified as new against the applied baseline), or `--fail-on-diagnostics`
  (any diagnostic).
- **Exit `2`** — the analysis could not run.

Every hook finding carries `scope`, normalized threshold metadata (`measured`,
`threshold`, `unit`, `direction`), and non-null `remediation`. The envelope also
includes `suppressed.count`, `ignored.paths`, and `config.schemaOk` /
`config.error` for config failures.

`suppressions` starts with one row per configured `sensitiveExclusions` entry,
in configuration order: `rule`, a single `path` string, `symbol` (always
present, `null` when the entry names none), `reason`, and `suppressed`. This
differs from `analyse` and `summary` — which publish `index` and a `paths` array
and omit `symbol` when unset — so a `gruff.analysis.v3` consumer cannot read
hook suppression rows unchanged. A configured row with `suppressed: 0` matched
nothing; it records that the exclusion is active, not that it hid a finding.

After the configured rows, `suppressions` includes the analysis run's audit rows
carrying a `source` label: `source: "built-in"` for files skipped by the shared
test, fixture, and example exclusion across security and sensitive-data rules,
`source: "inline"` for honoured third-party suppression comments, and
`source: "duplicate"` for merged duplicate dynamic-import claims.

`--changed-ranges` scopes `hook` at the finding's own reported span: a finding is
returned when its `line..endLine` intersects a changed range, and whole-file or
class-level aggregate findings are reported only when newly introduced versus a
`--baseline` / `--diff` base. This is hunk granularity — it does **not** widen a
changed range to its enclosing declaration the way `analyse --changed-scope
symbol` does, so a finding on an untouched line inside an edited symbol is
counted in `suppressed.count` rather than returned. Use `analyse --changed-scope
symbol` when you want whole-symbol attribution instead.

Use `--baseline <path>` with a `gruff.baseline.v3` file written by
`analyse --generate-baseline`, or use `--diff <ref|working-tree>` to compare
against a Git tree. A Git comparison keeps findings beyond the base occurrence
count. With an applied baseline, `--fail-on-new` gates on findings classified as
new.

Consumers can discover the supported flag names and ordering once:

```sh
uv run gruff-py hook --capabilities --format json
```

Use `hook --exclude-rule <rule-id>` when an agent harness needs execution-level
rule exclusion in the hook payload. The flag accepts comma-separated and
repeated values, and excluded rules do not run for that hook invocation.

## Gate The Changed Region With Analyse

Use changed-region flags with ordinary `--fail-on`. gruff-py filters findings
first, then applies the severity threshold to the retained findings:

```sh
# Exact line ranges from an editor or agent payload.
uv run gruff-py analyse src/foo.py \
  --changed-ranges "12-40,88-90" \
  --changed-scope symbol \
  --no-baseline \
  --format json \
  --fail-on warning

# Current working-tree diff.
uv run gruff-py analyse . \
  --diff=working-tree \
  --changed-scope symbol \
  --no-baseline \
  --fail-on warning

# Piped unified diff.
git diff | uv run gruff-py analyse . \
  --diff - \
  --changed-scope symbol \
  --no-baseline \
  --format json \
  --fail-on none
```

`--changed-scope symbol` keeps findings in a changed declaration even when the
finding's primary line is outside the edited hunk. `--changed-scope hunk` is
stricter and keeps only findings whose reported location intersects the changed
lines. Under `symbol`, whole-file and class-level aggregate findings are attributed to
their anchor line or header (such as file line 1 or the class declaration), so
an edit elsewhere in the file or class suppresses inherited aggregate debt. JSON
changed-region runs publish the excluded count at `summary.suppressedFindings`
and `diff.filteredFindings` so hooks can show how much same-file debt was left
non-blocking.

For CI workflows that must preserve whole-file aggregate signal on pull-request
diffs, run a full scan or a companion `--changed-scope hunk` scan. Full scans
still report every file-wide finding; hunk scans still use the finding's
reported span, so file-spanning findings remain visible when any changed line
intersects that span.

`--fail-on none` is useful when a local PostToolUse hook should print feedback
but never block the shell command. CI or a hard agent verification step should
use `--fail-on warning` or `--fail-on error`.

## Do Not Baseline Agent Output

Pass `--no-baseline` for local agent governance. A default
`gruff-baseline.json` is useful when adopting gruff on a legacy codebase, but it
can hide the finding the agent just introduced. The agent loop should make the
agent fix its own changed-region findings instead of suppressing them as known
debt.

Use baselines deliberately for adoption audits and branch-review workflows, not
as the default local hook policy.

## Respect Ignored Paths

`paths.ignore` is authoritative for directory scans, explicit file operands, and
diff/changed-region scans. A matching path emits no findings and appears in JSON
`paths.details` with the source and matched pattern.

Hooks can check scope without running analysis:

```sh
uv run gruff-py check-ignore --format json src/app.py generated/out.py
```

`check-ignore` shares the same engine as `analyse`, so its verdict matches what
the analyzer will skip.
