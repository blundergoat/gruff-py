# gruff-py — common dev tasks.
# Everything runs through `uv` so the venv is auto-managed.

.PHONY: help install test lint format typecheck check dev perf perf-quick perf-baseline clean precommit-install precommit-run

help:
	@echo "gruff-py — dev targets:"
	@echo "  install            Create .venv and install package with dev extras"
	@echo "  test               Run pytest"
	@echo "  lint               Run ruff check (with --fix)"
	@echo "  format             Run ruff format"
	@echo "  typecheck          Run mypy on src/"
	@echo "  check              lint + typecheck + test"
	@echo "  dev                Run gruff against its own src/ (dogfood)"
	@echo "  perf               Run scripts/test-performance.sh full suite"
	@echo "  perf-quick         Run scripts/test-performance.sh --quick (CI smoke)"
	@echo "  perf-baseline      Overwrite linux-x86_64 baseline with current run"
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
	uv run gruff-py analyse src/

perf:
	scripts/test-performance.sh --baseline scripts/performance-baselines/linux-x86_64.json

perf-quick:
	scripts/test-performance.sh --quick --baseline scripts/performance-baselines/linux-x86_64.json

perf-baseline:
	scripts/test-performance.sh --update-baseline scripts/performance-baselines/linux-x86_64.json

precommit-install:
	uv run pre-commit install

precommit-run:
	uv run pre-commit run --all-files

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache build dist *.egg-info coverage.xml htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
