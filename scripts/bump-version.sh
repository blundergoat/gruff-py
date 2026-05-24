#!/usr/bin/env bash
# scripts/bump-version.sh - bump gruff-py's release version.
#
# Updates the two files that must agree on the public version:
#   - pyproject.toml         project.version
#   - src/gruffpy/version.py VERSION
#
# Does NOT commit, tag, publish, or touch CHANGELOG.md. The user owns those
# steps; see docs/releasing.md for the full release checklist.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PYPROJECT="$ROOT_DIR/pyproject.toml"
VERSION_PY="$ROOT_DIR/src/gruffpy/version.py"

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
Usage: scripts/bump-version.sh <new-version>
       scripts/bump-version.sh --check
       scripts/bump-version.sh -h | --help

Bump gruff-py's public version in pyproject.toml and src/gruffpy/version.py.
Both files must agree; this script keeps them in lockstep.

Arguments:
  <new-version>   Target version, PEP 440 / semver style (e.g. 0.2.0, 1.0.0rc1).

Options:
  --check         Verify pyproject.toml and src/gruffpy/version.py agree.
                  Exits 0 if they match, 1 if they drift.
  -h, --help      Show this help.

This script does NOT:
  - commit, tag, or push (the user owns git operations)
  - edit CHANGELOG.md (move [Unreleased] entries manually per docs/releasing.md)
  - run release verification (see docs/releasing.md)

Examples:
  scripts/bump-version.sh 0.2.0
  scripts/bump-version.sh --check

Release verification after bumping:
  uv run ruff check src tests
  uv run ruff format --check src tests
  uv run mypy src
  uv run python -m gruffpy.command.rule_docs --check docs/rules.md
  uv run pytest
  uv build
USAGE
}

err() {
  printf '%s%s%s\n' "$RED" "$*" "$RESET" >&2
}

info() {
  printf '%s\n' "$*"
}

# Extract the version literal from pyproject.toml's [project] table.
read_pyproject_version() {
  # First `^version = "..."` after `[project]`, before the next table header.
  awk '
    /^\[project\][[:space:]]*$/ { in_project = 1; next }
    /^\[/                        { in_project = 0 }
    in_project && /^version[[:space:]]*=/ {
      match($0, /"[^"]*"/)
      print substr($0, RSTART + 1, RLENGTH - 2)
      exit
    }
  ' "$PYPROJECT"
}

read_version_py() {
  awk '
    /^VERSION[[:space:]]*=/ {
      match($0, /"[^"]*"/)
      print substr($0, RSTART + 1, RLENGTH - 2)
      exit
    }
  ' "$VERSION_PY"
}

# Accept PEP 440 / semver-ish: N.N.N optionally followed by a pre/post/dev tag.
# Examples that pass: 0.1.0, 1.2.3, 1.0.0rc1, 1.0.0a2, 0.2.0.dev1, 1.0.0.post1
validate_version() {
  local v="$1"
  if [[ ! "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-]?(a|b|rc|alpha|beta|dev|post)[0-9]+)?$ ]]; then
    err "Invalid version: '$v'"
    err "Expected MAJOR.MINOR.PATCH, optionally with a pre/post/dev tag (e.g. 1.0.0rc1)."
    return 1
  fi
}

# Portable in-place sed: works with both GNU and BSD sed.
sed_inplace() {
  local expr="$1"
  local file="$2"
  sed -E -i.bak "$expr" "$file"
  rm -f "${file}.bak"
}

check_files_exist() {
  local missing=0
  if [[ ! -f "$PYPROJECT" ]]; then
    err "Missing: $PYPROJECT"
    missing=1
  fi
  if [[ ! -f "$VERSION_PY" ]]; then
    err "Missing: $VERSION_PY"
    missing=1
  fi
  return "$missing"
}

cmd_check() {
  check_files_exist || return 1

  local pyproject_version version_py_version
  pyproject_version="$(read_pyproject_version)"
  version_py_version="$(read_version_py)"

  if [[ -z "$pyproject_version" ]]; then
    err "Could not read project.version from pyproject.toml"
    return 1
  fi
  if [[ -z "$version_py_version" ]]; then
    err "Could not read VERSION from src/gruffpy/version.py"
    return 1
  fi

  printf '  %-32s %s\n' "pyproject.toml" "$pyproject_version"
  printf '  %-32s %s\n' "src/gruffpy/version.py" "$version_py_version"

  if [[ "$pyproject_version" != "$version_py_version" ]]; then
    err "Version drift detected."
    err "Run: scripts/bump-version.sh <version> to reconcile."
    return 1
  fi

  printf '%s✔%s versions agree: %s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$pyproject_version" "$RESET"
}

cmd_bump() {
  local new_version="$1"

  validate_version "$new_version" || return 1
  check_files_exist || return 1

  local current_pyproject current_version_py
  current_pyproject="$(read_pyproject_version)"
  current_version_py="$(read_version_py)"

  if [[ -z "$current_pyproject" ]]; then
    err "Could not read project.version from pyproject.toml"
    return 1
  fi
  if [[ -z "$current_version_py" ]]; then
    err "Could not read VERSION from src/gruffpy/version.py"
    return 1
  fi

  if [[ "$current_pyproject" != "$current_version_py" ]]; then
    printf '%s!%s pyproject.toml (%s) and src/gruffpy/version.py (%s) disagree before bump; both will be set to %s.\n' \
      "$YELLOW" "$RESET" "$current_pyproject" "$current_version_py" "$new_version"
  fi

  if [[ "$current_pyproject" == "$new_version" && "$current_version_py" == "$new_version" ]]; then
    info "Already at $new_version; nothing to do."
    return 0
  fi

  # pyproject.toml: only touch the project.version line, leave other `version`
  # keys (e.g. python_version, target-version) untouched.
  sed_inplace "/^\[project\]/,/^\[/ s/^(version[[:space:]]*=[[:space:]]*\")[^\"]+(\")/\1${new_version}\2/" "$PYPROJECT"
  sed_inplace "s/^(VERSION[[:space:]]*=[[:space:]]*\")[^\"]+(\")/\1${new_version}\2/" "$VERSION_PY"

  local after_pyproject after_version_py
  after_pyproject="$(read_pyproject_version)"
  after_version_py="$(read_version_py)"

  if [[ "$after_pyproject" != "$new_version" || "$after_version_py" != "$new_version" ]]; then
    err "Bump failed."
    err "  pyproject.toml         = $after_pyproject (expected $new_version)"
    err "  src/gruffpy/version.py = $after_version_py (expected $new_version)"
    return 1
  fi

  printf '%s✔%s bumped %s%s%s → %s%s%s\n' \
    "$GREEN" "$RESET" \
    "$DIM" "$current_pyproject" "$RESET" \
    "$BOLD" "$new_version" "$RESET"
  printf '  %-32s %s\n' "pyproject.toml" "$after_pyproject"
  printf '  %-32s %s\n' "src/gruffpy/version.py" "$after_version_py"

  cat <<NEXT

Next steps (see docs/releasing.md for the full checklist):
  - Move CHANGELOG.md [Unreleased] entries into a new [${new_version}] section.
  - Run: uv run ruff check src tests && uv run ruff format --check src tests
  - Run: uv run mypy src && uv run python -m gruffpy.command.rule_docs --check docs/rules.md
  - Run: uv run pytest
  - Run: uv build
  - Review the diff, then commit and tag yourself (e.g. \`git tag v${new_version}\`).
NEXT
}

main() {
  if [[ $# -eq 0 ]]; then
    usage
    exit 2
  fi

  case "$1" in
    -h|--help)
      usage
      ;;
    --check)
      if [[ $# -gt 1 ]]; then
        err "--check takes no arguments"
        exit 2
      fi
      cmd_check
      exit $?
      ;;
    -*)
      err "Unknown option: $1"
      usage >&2
      exit 2
      ;;
    *)
      if [[ $# -gt 1 ]]; then
        err "Too many arguments"
        usage >&2
        exit 2
      fi
      cmd_bump "$1"
      exit $?
      ;;
  esac
}

main "$@"
