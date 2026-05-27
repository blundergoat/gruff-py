---
category: error-handling
last_reviewed: 2026-05-27
---

## Pattern: Raise a typed exception at the validation layer, convert to `click.ClickException` at the CLI boundary

**Context:** A loader, parser, or other deep-stack helper detects a user-actionable
problem (malformed config, missing required field, conflicting CLI flags expressed
as data, etc.) and needs to surface a clean, user-facing error - a one-line stderr
message that includes the remediation, plus a non-zero exit code, plus no Python
traceback. Multiple intermediate layers sit between the detection point and the
CLI command (in gruff-py: `ConfigLoader` -> `_load_analysis_config` -> `run_analysis`
-> `_run_analysis_for_cli` -> the Click command body). The temptation to catch
the exception at the first available layer and convert it to a diagnostic
record / fallback / silent default *is the wrong shape* (`.goat-flow/footguns/config.md`,
search: `swallowed into.*RunDiagnostic`).

**Approach:**

1. **Detection layer raises a typed exception** (e.g. `ConfigError`, `BaselineError`)
   with a message that includes the remediation directly in the string. The
   remediation should be a literal command the user can copy-paste, not a generic
   "fix your config" hint. Example from `src/gruffpy/config/loader.py`
   (search: `_validate_schema_version`):
   ```
   raise ConfigError(
       f"{source} is missing required 'schemaVersion'. "
       f"Expected {CONFIG_SCHEMA_VERSION!r}; "
       f"run `gruff-py init --force` to regenerate."
   )
   ```

2. **Intermediate layers do not catch** the typed exception. No `try: ... except
   ConfigError: return defaults, [diagnostic]` patterns. Let it propagate. If
   you need a `try/except` for some other reason at an intermediate layer,
   re-raise the typed exception explicitly so future readers see it is meant
   to escape.

3. **CLI boundary converts to `click.ClickException`.** In gruff-py this is
   `src/gruffpy/cli.py` (search: `def _run_analysis_for_cli`):
   ```python
   try:
       return run_analysis(...)
   except ConfigError as exc:
       raise click.ClickException(str(exc)) from exc
   ```
   `click.ClickException` prints `Error: <message>` to stderr and exits with
   code 1 by default - exactly the shape this pattern targets. No traceback,
   no `sys.exit` plumbing, no manual stderr writing.

4. **Background server / non-CLI caller catches broadly.** Long-running callers
   that cannot afford to abort the process (e.g. `dashboard_server.py`'s
   `except Exception as exc` around `run_analysis`) will catch the typed
   exception via their existing broad `except` and render it as part of their
   own error UI - the remediation text travels with the message string and
   surfaces there without special-casing.

5. **Verification is the closer.** `raise` is not the same as user-visible.
   ADR-019 originally shipped step 1 only - the validator raised `ConfigError`
   with the right message, but the runner caught it and turned it into a
   `RunDiagnostic` that the `summary` reporter never rendered. The whole
   `gruff-py summary .` command exited 0 with grade A on a malformed config,
   silently ignoring the user's settings. Do not consider this pattern
   applied until you have run the failing scenario through the real CLI
   command and confirmed the message lands on stderr with exit 1 and no
   `Traceback` in the output. An integration test in the shape of
   `tests/integration/test_cli_smoke.py` (search:
   `test_cli_summary_aborts_cleanly_when_config_missing_schema_version`)
   pins all three assertions in one place. Pair with CLAUDE.md
   hallucination red-flag #3 ("do not claim a fix works without running
   the reproduction steps that originally demonstrated the bug") - the
   same discipline applies to *new* validation, not just bugfixes.

This pattern is **not** for internal programming errors (`KeyError` on an unknown
rule id, an `AssertionError` on a broken invariant) - those should remain raw
exceptions so they fail loudly in development. It is specifically for errors
that have a meaningful remediation a user can act on.

**Anti-pattern: hard error with Node-style stack trace.** The sibling case is
gruff-ts's `throw new Error(...)` from `src/config.ts`'s `applySchemaVersionConfig`,
which dumps a Node stack trace through the user's terminal because no CLI-level
handler converts the exception. Same root cause as the swallow pattern - missing
a typed boundary - but failing loud-and-ugly instead of silent. The right shape
is the same on both sides: typed exception at detection, conversion at CLI
boundary.
