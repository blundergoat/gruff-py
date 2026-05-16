# Release Checklist

Use this checklist before publishing `0.1`.

## Version And Metadata

- Decide whether the release version is `0.1.0` or remains `0.1.0.dev0`.
- Update `pyproject.toml` `project.version`.
- Confirm `pyproject.toml` license metadata matches `LICENSE.md`.
- Add project URLs in `pyproject.toml` before PyPI publication if desired.
- Confirm the package name `gruff-py` is available before publishing.

## Documentation

- Review `README.md`.
- Review `CHANGELOG.md`.
- Review `LICENSE.md`.
- Review `SECURITY.md`.
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

Suggested flow:

```bash
uv build
uv publish
```

Use TestPyPI first if this is the first public package upload.
