#!/usr/bin/env bash
# scripts/publish-pypi.sh - publish gruff-py to PyPI.
#
# Verifies version agreement, runs preflight checks, builds, and uploads via
# `uv publish`. Reads UV_PUBLISH_TOKEN from the environment.
#
# Does NOT commit, tag, push, or edit CHANGELOG.md / version files. The user
# owns those steps; see docs/releasing.md for the full release checklist.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"

SKIP_CHECKS=0
SKIP_BUILD=0
ASSUME_YES=0
ALLOW_DIRTY=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  YELLOW=$'\033[33m'
  RESET=$'\033[0m'
else
  BOLD=''
  DIM=''
  GREEN=''
  RED=''
  YELLOW=''
  RESET=''
fi

usage() {
  cat <<'USAGE'
Usage: scripts/publish-pypi.sh [options]

Publish the gruff-py wheel and sdist to PyPI.

Options:
  --skip-checks    Skip preflight checks (ruff/mypy/pytest/rule-docs).
  --skip-build     Skip `uv build`; reuse existing dist/ contents.
  --yes, -y        Skip the interactive y/N confirmation.
  --allow-dirty    Allow uncommitted changes when publishing.
  -h, --help       Show this help.

Environment:
  UV_PUBLISH_TOKEN  PyPI API token. Required.
                      https://pypi.org/manage/account/token/
  NO_COLOR          Disable ANSI color output.

This script does NOT:
  - commit, tag, or push (the user owns git operations)
  - edit CHANGELOG.md (see docs/releasing.md)
  - bump versions (use scripts/bump-version.sh)

Examples:
  # Real release to PyPI, no prompts.
  UV_PUBLISH_TOKEN=pypi-... scripts/publish-pypi.sh --yes

  # Reuse a wheel you just built.
  UV_PUBLISH_TOKEN=pypi-... scripts/publish-pypi.sh --skip-build
USAGE
}

err() {
  printf '%s%s%s\n' "$RED" "$*" "$RESET" >&2
}

warn() {
  printf '%s%s%s\n' "$YELLOW" "$*" "$RESET" >&2
}

info() {
  printf '%s\n' "$*"
}

ok() {
  printf '%s✔%s %s\n' "$GREEN" "$RESET" "$*"
}

read_pyproject_version() {
  uv run python -c 'import tomllib, pathlib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])'
}

check_version_agreement() {
  if ! "$SCRIPT_DIR/bump-version.sh" --check >/dev/null; then
    err "Version drift between pyproject.toml and src/gruffpy/version.py."
    err "Run: scripts/bump-version.sh --check"
    return 1
  fi
}

check_clean_working_tree() {
  local status_output
  status_output="$(git -C "$ROOT_DIR" status --porcelain)"
  if [[ -z "$status_output" ]]; then
    return 0
  fi

  if [[ "$ALLOW_DIRTY" -eq 0 ]]; then
    err "Working tree has uncommitted changes:"
    printf '%s\n' "$status_output" | sed 's/^/    /' >&2
    err "Refuse to publish dirty state to PyPI. Commit or stash, then retry."
    err "Override with --allow-dirty if you really mean it."
    return 1
  fi
  warn "Working tree has uncommitted changes (proceeding because --allow-dirty was set)."
}

run_checks() {
  info "Running preflight checks (this is the same suite as scripts/preflight-checks.sh)..."
  "$SCRIPT_DIR/preflight-checks.sh" \
    --skip-build \
    --require-unreleased-version || return 1
}

clean_dist() {
  mkdir -p "$DIST_DIR"
  find "$DIST_DIR" -maxdepth 1 -type f \( -name '*.whl' -o -name '*.tar.gz' \) -delete
}

build_package() {
  info "Cleaning dist/ wheels and sdists..."
  clean_dist || return 1
  info "Running uv build..."
  uv build || return 1
  ok "Built."
}

verify_dist() {
  local version="$1"
  local wheel="$DIST_DIR/gruff_py-${version}-py3-none-any.whl"
  local sdist="$DIST_DIR/gruff_py-${version}.tar.gz"
  local missing=()
  [[ -f "$wheel" ]] || missing+=("$wheel")
  [[ -f "$sdist" ]] || missing+=("$sdist")
  if ((${#missing[@]} > 0)); then
    err "Missing expected dist artifacts:"
    for m in "${missing[@]}"; do
      err "  $m"
    done
    err "Re-run without --skip-build, or rebuild with: uv build"
    return 1
  fi

  local extras
  extras="$(find "$DIST_DIR" -maxdepth 1 -type f \( -name '*.whl' -o -name '*.tar.gz' \) ! -name "gruff_py-${version}*")"
  if [[ -n "$extras" ]]; then
    err "Unexpected dist artifacts (delete these or rebuild):"
    printf '%s\n' "$extras" | sed 's/^/    /' >&2
    return 1
  fi
}

confirm() {
  local prompt="$1"
  if ((ASSUME_YES)); then
    return 0
  fi
  printf '%s [y/N] ' "$prompt"
  local reply
  read -r reply || return 1
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

do_publish() {
  local version="$1"
  local publish_args=(
    "$DIST_DIR/gruff_py-${version}-py3-none-any.whl"
    "$DIST_DIR/gruff_py-${version}.tar.gz"
  )
  uv publish "${publish_args[@]}"
}

main() {
  while (($#)); do
    case "$1" in
      --pypi)
        ;;
      --skip-checks)
        SKIP_CHECKS=1
        ;;
      --skip-build)
        SKIP_BUILD=1
        ;;
      --yes | -y)
        ASSUME_YES=1
        ;;
      --allow-dirty)
        ALLOW_DIRTY=1
        ;;
      -h | --help)
        usage
        return 0
        ;;
      *)
        err "Unknown option: $1"
        usage >&2
        return 2
        ;;
    esac
    shift
  done

  cd "$ROOT_DIR" || return 1

  if ! command -v uv >/dev/null 2>&1; then
    err "uv is not on PATH. Install: https://docs.astral.sh/uv/"
    return 127
  fi

  if [[ -z "${UV_PUBLISH_TOKEN:-}" ]]; then
    cat >&2 <<'TOKEN_HELP'
  read -rsp "PyPI token: " UV_PUBLISH_TOKEN; echo
  export UV_PUBLISH_TOKEN
  scripts/publish-pypi.sh

  Get the token from:

  https://pypi.org/manage/account/token/
TOKEN_HELP
    return 1
  fi

  check_version_agreement || return 1
  local version
  version="$(read_pyproject_version)"
  if [[ -z "$version" ]]; then
    err "Could not read project.version from pyproject.toml"
    return 1
  fi

  check_clean_working_tree || return 1

  if ((SKIP_CHECKS == 0)); then
    run_checks || return 1
  else
    warn "Skipping preflight checks (--skip-checks)."
  fi

  if ((SKIP_BUILD == 0)); then
    build_package || return 1
  else
    warn "Skipping uv build (--skip-build)."
  fi

  verify_dist "$version" || return 1

  printf '\n'
  printf '  About to publish %sgruff-py %s%s to %s\n' "$BOLD" "$version" "$RESET" "${RED}${BOLD}PyPI (production)${RESET}"
  printf '    %s%s%s\n' "$DIM" "$DIST_DIR/gruff_py-${version}-py3-none-any.whl" "$RESET"
  printf '    %s%s%s\n\n' "$DIM" "$DIST_DIR/gruff_py-${version}.tar.gz" "$RESET"

  if ! confirm "Proceed?"; then
    info "Aborted."
    return 1
  fi

  do_publish "$version" || return 1
  ok "Published gruff-py $version to PyPI."

  cat <<TAG
Next steps (see docs/releasing.md):
  - Tag the release commit: git tag v${version}
  - Push the tag:           git push --tags
  - Draft GitHub release notes from CHANGELOG.md [${version}].
TAG
}

main "$@"
