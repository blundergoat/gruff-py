# Security Policy

Repo-local calibration for `goat-security`. This policy narrows what counts as a
finding in this project; it does not suppress an observed exploit path or
downgrade a verified finding.

## Threat Surface

gruff-py is a local static analyser with no authentication layer, no service
account, and no outbound network request. Its trust boundaries are local
filesystem inputs: user-supplied paths, `--config`, `pyproject.toml`, and the
source files it reads. Rank findings against that shape before reaching for
web-application categories.

Highest-value surfaces, in order:

1. `gruff-py dashboard` - the stdlib `ThreadingHTTPServer` under
   `src/gruffpy/command/dashboard_server.py` and the HTML it serves from
   `src/gruffpy/command/dashboard_page_renderer.py`.
2. Agent guardrail scripts under `.goat-flow/hooks/`, which run on real agent
   tool calls.
3. Rule code that reads or reports source text, particularly the
   `sensitive_data.*` scanners that match secrets and PHI.
4. Supply chain: `pyproject.toml`, `uv.lock`, `package.json`,
   `.github/workflows/ci.yml`, and `scripts/publish-pypi.sh`.

## Auth Model Assumptions

The dashboard has no authentication and is not intended to gain one. It binds
`127.0.0.1` by default and is a single-user local development UI, not a shared
service. Treat "the dashboard has no login" as accepted design, not a finding.

Still in scope, and still reportable:

- A bind address that is not loopback, or an option that makes one reachable.
- Missing `Host`/`Origin` validation that lets a browser page on another origin
  drive the server.
- Interpolated values reaching dashboard HTML, iframe metadata, loading frames,
  or error frames without escaping.
- Any path where a scan target's contents can influence the served page.

## Secret Classes and Handling Rules

The repo holds no production secrets. The classes that matter are the ones that
flow *through* the tool:

- Findings from `sensitive_data.*` rules quote matched source. Reports, SARIF
  output, baselines, and hotspot files may therefore carry real secrets from the
  scanned project. Anything that widens what is quoted, or writes it somewhere
  new, is a finding.
- PyPI credentials used by `scripts/publish-pypi.sh` and CI. Never read, echo,
  or persist them.
- `.env*`, `**/secrets/**`, keys, and cloud credential files are denied to
  agents by `.claude/settings.json` and the shared deny hook. A change that
  narrows those deny lists is a finding.

## Deployment Boundaries

gruff-py ships as a PyPI package built by Hatchling and runs on a developer
machine or in CI. It never runs as a network service. Findings that assume a
hosted multi-tenant deployment do not apply; say so and move on rather than
filing them as theoretical.

Published artifacts must not contain agent or workspace files. Excluded:
`.agents/`, `.claude/`, `.codex/`, `.github/`, `.goat-flow/`, `AGENTS.md`, and
`CLAUDE.md`.

## Forbidden Services and Actions

- No outbound network calls from analyser runtime code.
- No telemetry, crash reporting, or usage analytics.
- No new runtime dependency without an explicit decision; the dashboard stays on
  the standard library with inline HTML, CSS, and JS.
- Agents must not run `git commit`, `git push`, or publish; the shipped deny
  hooks enforce this.

## Approved Crypto

Hashing is identity-only, never a security control. Fingerprints and stable
identities take the first 16 hex characters of a SHA-256 over a byte layout that
reproduces gruff-php exactly (`src/gruffpy/finding/fingerprint.py`, search:
`_php_compatible_sha256_prefix`). Do not flag that truncation or that digest
choice as a crypto weakness, and do not "upgrade" either - the bytes are a
cross-implementation contract covered by
`.goat-flow/learning-loop/footguns/compatibility.md`.

The `security.weak-crypto` rule that gruff-py *reports on* is a separate concern
and its own thresholds apply.

## Known Accepted Risks

- Heuristic AST analysis produces false positives by design. A rule that
  over-matches is a quality finding for `/goat-review`, not a security finding.
- Rule code executes no scanned source: it parses to AST and never imports,
  `eval`s, or runs the target project. Any change to that property is a
  Critical finding.
