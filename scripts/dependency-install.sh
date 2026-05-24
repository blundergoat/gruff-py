#!/usr/bin/env bash
# scripts/dependency-install.sh - sync gruff-py's local dependency environment.
#
# Installs the project with all optional extras and development tooling using
# uv.lock by default. Use scripts/dependency-update.sh when you intend to
# refresh dependency versions.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

RUN_AUDIT=1
CHECK_ONLY=0
LOCK_ARGS=(--locked)
PYTHON_ARGS=()
UV_EXTRA_ARGS=()

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
Usage: scripts/dependency-install.sh [options] [-- uv-sync-args...]

Sync gruff-py's local uv environment from uv.lock:
  uv sync --all-extras --dev --locked --reinstall-package gruff-py

Options:
  --python PYTHON  Sync with a specific Python interpreter or version.
  --check          Check whether the environment is already synchronized.
  --update-lock    Allow uv to update uv.lock during sync.
  --no-audit       Skip the pip-audit vulnerability check after sync.
  -h, --help       Show this help.

Any arguments after `--` are passed through to `uv sync`.
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

sync_dependencies() {
  local sync_args=(--all-extras --dev)

  if ((CHECK_ONLY)); then
    sync_args+=(--check)
  else
    sync_args+=(--reinstall-package gruff-py)
  fi

  sync_args+=("${LOCK_ARGS[@]}" "${PYTHON_ARGS[@]}" "${UV_EXTRA_ARGS[@]}")

  printf 'Running: uv sync'
  printf ' %q' "${sync_args[@]}"
  printf '\n'
  uv sync "${sync_args[@]}"
}

main() {
  while (($#)); do
    case "$1" in
      --python)
        [[ $# -ge 2 ]] || {
          err "Missing value for --python"
          usage >&2
          return 64
        }
        PYTHON_ARGS=(--python "$2")
        shift
        ;;
      --check)
        CHECK_ONLY=1
        ;;
      --update-lock)
        LOCK_ARGS=()
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
        UV_EXTRA_ARGS+=("$@")
        break
        ;;
      *)
        err "Unknown option: $1"
        usage >&2
        return 64
        ;;
    esac
    shift
  done

  cd "$ROOT_DIR" || return 1
  require_uv || return $?

  if ((CHECK_ONLY && RUN_AUDIT)); then
    warn "Skipping dependency audit in --check mode."
    RUN_AUDIT=0
  fi

  sync_dependencies || return 1

  if ((RUN_AUDIT)); then
    dependency_audit || return 1
  fi

  ok "Dependencies are ready."
}

main "$@"
