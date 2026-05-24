#!/usr/bin/env bash
# scripts/dependency-update.sh - update gruff-py's uv dependency lock.
#
# Updates uv.lock, syncs the local environment, and runs the dependency audit.
# With no package arguments, all dependencies are eligible for upgrade. With
# package arguments or --package, only those packages are targeted.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

RUN_SYNC=1
RUN_AUDIT=1
DRY_RUN=0
PYTHON_ARGS=()
PACKAGES=()
UV_LOCK_EXTRA_ARGS=()
UV_SYNC_EXTRA_ARGS=()

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  YELLOW=$'\033[33m'
  RESET=$'\033[0m'
else
  GREEN=''
  RED=''
  YELLOW=''
  RESET=''
fi

usage() {
  cat <<'USAGE'
Usage: scripts/dependency-update.sh [options] [packages...] [-- uv-lock-args...]

Update gruff-py's dependency lock and local environment. The sync step
reinstalls gruff-py so console entry points stay aligned with pyproject.toml.

Examples:
  scripts/dependency-update.sh
  scripts/dependency-update.sh ruff mypy
  scripts/dependency-update.sh --package pip-audit --dry-run

Options:
  -P, --package PACKAGE  Upgrade one package. May be repeated.
  --python PYTHON       Resolve and sync with a specific Python interpreter.
  --dry-run             Preview lockfile changes; skip sync and audit.
  --no-sync             Update uv.lock but do not sync the environment.
  --no-audit            Skip the pip-audit vulnerability check.
  -h, --help            Show this help.

Any arguments after `--` are passed through to `uv lock`.
USAGE
}

err() {
  printf '%s%s%s\n' "$RED" "$*" "$RESET" >&2
}

warn() {
  printf '%s%s%s\n' "$YELLOW" "$*" "$RESET" >&2
}

ok() {
  printf '%s%s%s\n' "$GREEN" "$*" "$RESET"
}

require_uv() {
  if ! command -v uv >/dev/null 2>&1; then
    err "uv is not on PATH. Install: https://docs.astral.sh/uv/"
    return 127
  fi
}

dependency_audit() {
  uv run pip-audit --skip-editable --progress-spinner off
}

update_lock() {
  local lock_args=()
  local package

  if ((DRY_RUN)); then
    lock_args+=(--dry-run)
  fi

  if ((${#PACKAGES[@]} == 0)); then
    lock_args+=(--upgrade)
  else
    for package in "${PACKAGES[@]}"; do
      lock_args+=(--upgrade-package "$package")
    done
  fi

  lock_args+=("${PYTHON_ARGS[@]}" "${UV_LOCK_EXTRA_ARGS[@]}")

  printf 'Running: uv lock'
  printf ' %q' "${lock_args[@]}"
  printf '\n'
  uv lock "${lock_args[@]}"
}

sync_dependencies() {
  local sync_args=(--all-extras --dev --reinstall-package gruff-py)

  sync_args+=("${PYTHON_ARGS[@]}" "${UV_SYNC_EXTRA_ARGS[@]}")

  printf 'Running: uv sync'
  printf ' %q' "${sync_args[@]}"
  printf '\n'
  uv sync "${sync_args[@]}"
}

main() {
  while (($#)); do
    case "$1" in
      -P|--package)
        [[ $# -ge 2 ]] || {
          err "Missing value for $1"
          usage >&2
          return 64
        }
        PACKAGES+=("$2")
        shift
        ;;
      --python)
        [[ $# -ge 2 ]] || {
          err "Missing value for --python"
          usage >&2
          return 64
        }
        PYTHON_ARGS=(--python "$2")
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        ;;
      --no-sync)
        RUN_SYNC=0
        ;;
      --no-audit)
        RUN_AUDIT=0
        ;;
      -h|--help)
        usage
        return 0
        ;;
      --)
        shift
        UV_LOCK_EXTRA_ARGS+=("$@")
        break
        ;;
      -*)
        err "Unknown option: $1"
        usage >&2
        return 64
        ;;
      *)
        PACKAGES+=("$1")
        ;;
    esac
    shift
  done

  cd "$ROOT_DIR" || return 1
  require_uv || return $?

  if ((DRY_RUN)); then
    RUN_SYNC=0
    RUN_AUDIT=0
    warn "Dry run: sync and audit will be skipped."
  fi

  update_lock || return 1

  if ((RUN_SYNC)); then
    sync_dependencies || return 1
  fi

  if ((RUN_AUDIT)); then
    dependency_audit || return 1
  fi

  ok "Dependency update complete."
}

main "$@"
