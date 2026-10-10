# Dashboard

`gruff-py dashboard` serves a local browser UI for repeated scans.

```bash
gruff-py dashboard src/ --report-interactive
```

Default URL:

```text
http://127.0.0.1:8765/
```

## Controls

The dashboard supports controls for shipped `gruff-py analyse` features:

- project root
- paths
- config path
- no config
- fail threshold
- include ignored directories
- interactive HTML finding filters

The dashboard intentionally does not expose unsupported workflows such as
baseline review, diff-only scans, trend history, mutation analysis, branch
review, editor links, async cancellation, or websocket updates.

## Options

```bash
gruff-py dashboard [PATHS]...
```

| Option | Meaning |
|---|---|
| `--host 127.0.0.1` | Host interface to bind |
| `--allow-public` | Acknowledge the risk of binding the unauthenticated dashboard to a non-loopback host |
| `--port 8765` | Port to bind; use `0` for an OS-selected port |
| `--scan-timeout <seconds>` | Accepted for cross-port compatibility; not implemented in gruff-py |
| `--project <path>` | Project root to analyse |
| `--project-root <path>` | Alias for `--project` |
| `--config <path>` | Initial config path |
| `--no-config` | Skip config loading |
| `--diff` | Accepted for cross-port compatibility; not implemented in gruff-py |
| `--fail-on <severity>` | Initial fail threshold |
| `--include-ignored` | Scan default-ignored directories and `.gitignore` exclusions |
| `--report-interactive` | Enable HTML finding filters |

## Default Severity Gate

The form's initial **fail threshold** dropdown can be seeded from the loaded
config so every dashboard launch starts at the project's preferred default:

```yaml
schemaVersion: gruff-py.config.v0.1
failOn:
  dashboard: warning
```

The CLI `--fail-on` flag overrides the config value when set; the user can
still change the threshold per-scan in the dropdown. See
[Configuration → Severity Gate](configuration.md#severity-gate).

## HTTP Routes

| Route | Meaning |
|---|---|
| `/` | Dashboard shell |
| `/scan` | Runs the analysis and returns HTML for the iframe |
| `/health` | Returns `ok` |
| `/favicon.ico` | Empty 204 response |

## Security Model

The dashboard has no authentication. It is intended for local development and
binds to `127.0.0.1` by default.

`gruff-py` refuses non-loopback hosts unless you pass `--allow-public`. The flag
is an acknowledgment, not access control: startup prints a warning, and remote
users can use the unauthenticated dashboard to scan any directory readable by
the server process.

Keep the dashboard on `127.0.0.1`, `localhost`, or `::1` unless remote access is
intentional. Authentication and project-root confinement are deferred security
design work and are not provided by `--allow-public`.
