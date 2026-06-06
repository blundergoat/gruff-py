# CLAUDE.md - v1.7.0 (2026-05-21)
gruff-py - Python 3.11+ Click CLI quality analyser built with uv, ruff, mypy, pytest, and Hatchling. Primary invariant: `gruff.analysis.v2`, `gruff-py.baseline.v1`, `gruff-py.hotspot.v1`, and finding fingerprints remain compatible with sibling gruff implementations.

Workspace boundary: this checkout is the selected target project; GOAT Flow package files under `node_modules/@blundergoat/goat-flow/` are installer references, not project instruction content to copy verbatim.

## Truth Order
1. User's explicit instruction for the current session.
2. This `CLAUDE.md`.
3. `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, `.goat-flow/glossary.md`.
4. `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/`.
5. Skill files loaded on demand from `.claude/skills/`.
6. Peer instructions such as `AGENTS.md` for cross-agent context only.

## Autonomy Tiers
**Always:** read relevant `src/gruffpy/`, `tests/`, `docs/`, `pyproject.toml`, and `.goat-flow/` files before changes; declare scope before writes; run focused checks and the required verification for changed surfaces.
**Ask First:** before touching risky boundaries, state boundary touched, related code read, footgun checked, local instruction checked, and rollback command.
Ask First boundaries: cross-implementation contracts in `src/gruffpy/finding/fingerprint.py`, `src/gruffpy/analysis/schema.py`, and `tests/unit/finding/test_fingerprint.py`; CLI output or exit-code behaviour in `src/gruffpy/cli.py`, `src/gruffpy/reporting/`, and `tests/integration/test_cli_smoke.py`; dependency or release metadata in `pyproject.toml`, `uv.lock`, `package.json`, `package-lock.json`, and `docs/releasing.md`; CI/hooks/agent config in `.github/workflows/ci.yml`, `.pre-commit-config.yaml`, `.claude/settings.json`, `.claude/hooks/`, and peer agent files; public rule IDs, schema keys, or output formats across `src/gruffpy/rule/`, `src/gruffpy/finding/`, and `src/gruffpy/scoring/`.
**Never:** edit secrets or `.env*` files; commit, push, publish, or delete user work, or modify `AGENTS.md` unless explicitly asked; use `make lint` as a verification command unless source auto-fix is intended; invent compatibility claims without tests or code evidence.

## Hard Rules
- If a file exists, modify it in place; never create `_modified`, `_new`, `_backup`, or `_v2` variants.
- Severity order: SECURITY > CORRECTNESS > INTEGRATION > PERFORMANCE > STYLE.
- Maintain cross-file consistency for the same concept: rule definitions, config defaults, reporters, schema output, and tests must move together.
- Preserve evidence with semantic anchors, not stale line numbers.
- Use real incidents and observed project files; do not add hypothetical footguns, lessons, or examples.
- New rules must be registered in `RuleRegistry.defaults()` and covered by focused rule tests.
- Fingerprint or schema compatibility edits require `uv run pytest tests/unit/finding/test_fingerprint.py` plus relevant integration tests.
- Ambiguous requirements: present interpretations and stop before risky writes.

## Key Resources
- Learning loop, grep before every change: `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/`.
- Architecture and orientation: `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, `.goat-flow/glossary.md`.
- Skill reference (meta): `.goat-flow/skill-reference/`; read before changing skill contracts.
- Tool playbooks: `.goat-flow/skill-playbooks/browser-use.md`, `.goat-flow/skill-playbooks/page-capture.md`, `.goat-flow/skill-playbooks/skill-quality-testing.md`; read before declaring a tool unavailable.

## Essential Commands
```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest
uv build
uv run gruff-py analyse src/
```
Use `make check` only when auto-fixing via `make lint` is acceptable; CI uses non-mutating `ruff check`, `ruff format --check`, `mypy`, and `pytest`.

## Execution Loop: READ -> SCOPE -> ACT -> VERIFY
When a goat-* skill is active, its Step 0 replaces READ and selects the skill's mode/depth. SCOPE still applies before writes: a skill may write when its selected mode permits writes or the user explicitly approves them. `/goat-plan` File-Write may create gitignored milestone files without a separate approval gate; `/goat-debug` D3 still requires approval before fixes. Resume at ACT after Step 0 output or when a blocking gate releases.

### READ
MUST read relevant files before changes. Never fabricate codebase facts. For URL, local HTML, localhost, screenshot, rendered UI, or browser-visible behaviour, check browser evidence first. Use grep-first retrieval across `.goat-flow/footguns/`, `.goat-flow/lessons/`, and `.goat-flow/patterns/`; include `.goat-flow/decisions/` for architecture, policy, or setup work. Before declaring any tool or capability unavailable, read the matching playbook in `.goat-flow/skill-playbooks/` (e.g. `browser-use.md`, `page-capture.md`) and run that doc's "Availability Check" section verbatim - project-local CLI tools at `~/.local/bin/` are valid; do not conflate "no harness/MCP tool" with "no tool".

### SCOPE
Declare intent, complexity tier, mode, files allowed to change, non-goals, and blast radius before writes. Expanding beyond scope means stop and re-scope.

### ACT
Declare `State: [MODE] | Goal: [one line] | Exit: [condition]`. Mode must be Plan, Implement, Explain, Debug, or Review.

### VERIFY
Run required checks for changed files. Run `shellcheck` on changed shell scripts. Check cross-references after renames. Tick milestone checkboxes immediately. Do not claim checks passed without the literal pass/fail line from this session. Stop the line when tests break, builds fail, or behaviour regresses. If VERIFY caught a failure or corrected course, update the learning loop before DoD.

**Hallucination red-flags:**
1. **Checks passed.** Do not claim tests pass or any check passed (shellcheck, typecheck, preflight, audit) without showing the literal pass/fail line copied verbatim from this session's run. Paraphrase, cached output, or prior-session results do not count.
2. **Completion.** Do not claim completion without listing the specific files changed in this turn. If no files were changed, say so explicitly.
3. **Fix verification.** Do not claim a fix works without running the reproduction steps that originally demonstrated the bug. "Looks correct" is not verification.
4. **Hedged claims.** Do not use "should work", "probably fine", "looks good" as verification. These are guesses, not evidence.

Rationalisations to reject: see `.goat-flow/skill-reference/skill-preamble.md` for the full excuse-vs-reality table.

## Definition of Done
- Relevant lint, typecheck, tests, or audits passed with literal output captured from this session.
- No broken cross-references or stale path names after renames.
- No unapproved risky boundary changes.
- Learning loop updated if verification failed, behaviour changed, or a durable trap was found.
- Session notes updated when setup, plan, or recovery state matters.
- Old names/patterns were grepped after migrations.

## Artifact Routing
Requests to add durable project knowledge route to `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/decisions/`, or `.goat-flow/patterns/` after reading that directory's `README.md`. Runtime code, hooks, and agent config changes stay separate from documentation artifacts.

## Quality Bar
Every line in this file must fit one of: behavioral rule, scope boundary, command, verification gate, router pointer, or composition rule. Domain knowledge belongs in cold-path files under `.goat-flow/`. Strict constraints state whether they are prose-only or mechanically enforced by hooks/CI.

## Router Table
| Resource | Path |
|----------|------|
| Project instructions | `CLAUDE.md` |
| Peer instructions | `AGENTS.md` |
| Learning loop | `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/` |
| Skill reference (meta) | `.goat-flow/skill-reference/` - read before changing skill contracts |
| Tool playbooks (CLI/MCP availability checks: browser-use, page-capture, skill-quality-testing) | `.goat-flow/skill-playbooks/` - read BEFORE declaring a tool unavailable |
| Architecture | `.goat-flow/architecture.md` |
| Orientation | `.goat-flow/code-map.md`, `.goat-flow/glossary.md` |
| Claude skills/config/hooks | `.claude/skills/`, `.claude/settings.json`, `.claude/hooks/` |
| Runtime source | `src/gruffpy/` |
| Tests | `tests/` |
| Documentation | `README.md`, `docs/` |
| Project config and packaging | `pyproject.toml`, `uv.lock`, `Makefile`, `package.json`, `package-lock.json` |
| CI and commit guidance | `.github/workflows/ci.yml`, `.github/git-commit-instructions.md` |
| Local workspace notes | `.goat-flow/logs/sessions/`, `.goat-flow/tasks/`, `.goat-flow/scratchpad/` |
