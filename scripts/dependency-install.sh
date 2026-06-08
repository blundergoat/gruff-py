#!/usr/bin/env bash
# scripts/dependency-install.sh - sync gruff-py's local dependency environment.
#
# Installs the project with all optional extras and development tooling using
# uv.lock, then installs the npm dependencies (goat-flow agent tooling) from
# package-lock.json. Use scripts/dependency-update.sh when you intend to
# refresh dependency versions.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

RUN_AUDIT=1
RUN_NPM=1
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

Sync gruff-py's local environments from their lockfiles:
  uv sync --all-extras --dev --locked --reinstall-package gruff-py
  npm ci   (installs the goat-flow npm tooling from package-lock.json)

Options:
  --python PYTHON  Sync with a specific Python interpreter or version.
  --check          Check whether the environments are already synchronized.
  --update-lock    Allow uv and npm to update their lockfiles during sync.
  --no-audit       Skip the pip-audit vulnerability check after sync.
  --no-npm         Skip installing npm dependencies.
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

npm_project_present() {
  [[ -f "$ROOT_DIR/package.json" ]]
}

require_npm() {
  if ! command -v npm >/dev/null 2>&1; then
    err "npm is not on PATH but package.json is present (goat-flow ships as an npm package). Install Node.js: https://nodejs.org/"
    return 127
  fi
}

sync_npm() {
  local npm_args

  if ((CHECK_ONLY)); then
    npm_args=(ci --dry-run)
  elif ((${#LOCK_ARGS[@]} == 0)); then
    npm_args=(install)
  else
    npm_args=(ci)
  fi

  printf 'Running: npm'
  printf ' %q' "${npm_args[@]}"
  printf '\n'
  npm "${npm_args[@]}"
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
      --no-npm)
        RUN_NPM=0
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

  if ((RUN_NPM)) && npm_project_present; then
    require_npm || return $?
  else
    RUN_NPM=0
  fi

  if ((CHECK_ONLY && RUN_AUDIT)); then
    warn "Skipping dependency audit in --check mode."
    RUN_AUDIT=0
  fi

  sync_dependencies || return 1

  if ((RUN_NPM)); then
    sync_npm || return 1
  fi

  if ((RUN_AUDIT)); then
    dependency_audit || return 1
  fi

  ok "Dependencies are ready."
}

main "$@"
