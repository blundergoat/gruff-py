# gruff-py — common dev tasks.
# Everything runs through `uv` so the venv is auto-managed.

.PHONY: help install test lint format typecheck check dev clean precommit-install precommit-run

help:
	@echo "gruff-py — dev targets:"
	@echo "  install            Create .venv and install package with dev extras"
	@echo "  test               Run pytest"
	@echo "  lint               Run ruff check (with --fix)"
	@echo "  format             Run ruff format"
	@echo "  typecheck          Run mypy on src/"
	@echo "  check              lint + typecheck + test"
	@echo "  dev                Run gruff against its own src/ (dogfood)"
	@echo "  precommit-install  Install pre-commit hooks"
	@echo "  precommit-run      Run pre-commit on all files"
	@echo "  clean              Remove build artifacts and tool caches"

install:
	uv venv --python 3.12
	uv pip install -e ".[dev]"

test:
	uv run pytest

lint:
	uv run ruff check --fix src tests

format:
	uv run ruff format src tests

typecheck:
	uv run mypy src

check: lint typecheck test

dev:
	uv run gruff analyse src/

precommit-install:
	uv run pre-commit install

precommit-run:
	uv run pre-commit run --all-files

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache build dist *.egg-info coverage.xml htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
