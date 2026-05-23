# Release Checklist

Use this checklist for `0.1.x` and subsequent releases.

## Version And Metadata

- Bump `project.version` in `pyproject.toml`.
- Bump `VERSION` in `src/gruffpy/version.py` so it matches.
- Confirm `pyproject.toml` `license` and `LICENSE.md` agree.
- Add or confirm project URLs in `pyproject.toml` for PyPI display.
- Confirm the package name `gruff-py` is still owned by the project on PyPI.

## Documentation

- Move the staged entries from `CHANGELOG.md` `[Unreleased]` to a new dated
  release section.
- Review `README.md` status, install, and rule-count claims against the
  registry.
- Review `LICENSE.md` and `SECURITY.md`.
- Confirm examples use commands that work from a clean checkout.
- Confirm screenshots or dashboard artifacts are not accidentally committed
  unless intentionally part of release docs.

## Verification

Run non-mutating checks:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest
```

Regenerate and verify the rule catalogue doc:

```bash
uv run python -m gruffpy.command.rule_docs --check docs/RULES.md
```

Build the package:

```bash
uv build
```

Inspect the wheel and source distribution:

```bash
tar -tf dist/*.tar.gz | head
python -m zipfile --list dist/*.whl | head
```

Smoke-test the built wheel in a clean environment before publishing.

## Compatibility Checks

- Confirm `gruff-py.analysis.v1` has not changed unexpectedly.
- Confirm `gruff-py.hotspot.v1` has not changed unexpectedly.
- Confirm `gruff-py.baseline.v1` remains reserved for cross-implementation use.
- Confirm fingerprint golden tests pass.
- Confirm report format names are documented and implemented.

## Publishing

Only publish after metadata, license, docs, and verification are settled.

Use `scripts/publish-pypi.sh`. It re-runs preflight checks, rebuilds the
wheel and sdist, verifies them against the current version, prompts for
confirmation, and uploads via `uv publish`. It does **not** commit, tag,
or push.

The script reads `UV_PUBLISH_TOKEN` from the environment. Get tokens at
<https://pypi.org/manage/account/token/> and
<https://test.pypi.org/manage/account/token/>.

Validate on TestPyPI first:

```bash
UV_PUBLISH_TOKEN=<test-pypi-token> scripts/publish-pypi.sh
```

Then publish to PyPI:

```bash
UV_PUBLISH_TOKEN=<pypi-token> scripts/publish-pypi.sh --pypi
```

Run `scripts/publish-pypi.sh --help` for `--skip-checks`, `--skip-build`,
`--yes`, and `--allow-dirty`.

## Tag And Announce

- Tag the commit (e.g. `git tag v0.1.0 && git push --tags`).
- Draft GitHub release notes from the new `CHANGELOG.md` section.
