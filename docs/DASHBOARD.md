# Dashboard

`gruff dashboard` serves a local browser UI for repeated scans.

```bash
gruff dashboard src/ --report-interactive
```

Default URL:

```text
http://127.0.0.1:8765/
```

## Controls

The dashboard supports controls for shipped `gruff analyse` features:

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
gruff dashboard [PATHS]...
```

| Option | Meaning |
|---|---|
| `--host 127.0.0.1` | Host interface to bind |
| `--port 8765` | Port to bind; use `0` for an OS-selected port |
| `--project <path>` | Project root to analyse |
| `--project-root <path>` | Alias for `--project` |
| `--config <path>` | Initial config path |
| `--no-config` | Skip config loading |
| `--fail-on <severity>` | Initial fail threshold |
| `--include-ignored` | Scan default-ignored directories and `.gitignore` exclusions |
| `--report-interactive` | Enable HTML finding filters |

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

Only bind to a non-loopback host when you understand the risk of exposing local
project paths and static-analysis output on your network.
