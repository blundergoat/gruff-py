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
uv run python -m gruffpy.command.rule_docs --write docs/rules.md
uv run python -m gruffpy.command.rule_docs --check docs/rules.md
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

- Confirm `gruff.analysis.v2` has not changed unexpectedly.
- Confirm `gruff-py.hotspot.v1` has not changed unexpectedly.
- Confirm `gruff-py.baseline.v1` remains reserved for cross-implementation use.
- Confirm fingerprint golden tests pass (`tests/unit/finding/test_fingerprint.py`).
- Confirm `stableIdentity` shape tests pass (`tests/unit/finding/test_stable_identity.py`); the line-insensitive identity must stay byte-equivalent across ports.
- Confirm report format names are documented and implemented.

## Tag

Tag and push the release commit before publishing (e.g. `git tag v0.3.1 && git push --tags`).

## Publishing

Only publish after metadata, license, docs, verification, and the release tag
are settled.

Suggested flow:

```bash
uv build
uv publish
```

Use `scripts/publish-pypi.sh` when you want the local preflight, build, and
artifact checks to run before publishing. The script allows the release tag to
exist before publishing and fails only when the current version already exists
on PyPI.

## Announce

- Draft GitHub release notes from the new `CHANGELOG.md` section.
