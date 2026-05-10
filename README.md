# gruff-py

Python project quality analyser. Walks a project tree, applies rules across ten quality
pillars (size, complexity, dead-code, waste, naming, documentation, modernisation,
security, sensitive-data, test-quality), and emits a scored A–F report.

A Python port of [`gruff-php`](../gruff-php). Cross-implementation baseline format
(`gruff.baseline.v1`) and report schema (`gruff.analysis.v1`) are preserved byte-for-byte.

## Status

`0.1.0-dev` — pre-release. Foundational scaffolding and the first rule
(`size.file-length`) are in place. Rule catalogue is being built out.

## Quick start

```bash
pip install -e ".[dev]"
gruff analyse src/
```

Output formats: `text` (default), `json`. Exit codes: `0` clean, `1` fail-threshold
tripped, `2` diagnostic.

## Configuration

`pyproject.toml`, under `[tool.gruff]`:

```toml
[tool.gruff.paths]
ignore = ["tests/fixtures/**"]

[tool.gruff.rules."size.file-length"]
thresholds = { warning = 400, error = 800 }
```
