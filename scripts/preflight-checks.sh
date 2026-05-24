#!/usr/bin/env bash
# scripts/preflight-checks.sh - gruff-py local preflight gate.
#
# Runs Python static checks, docs checks, gruff-py summary, tests, and package
# build. Build artifacts are written under dist/, which is gitignored in this
# project.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
RUN_BUILD=1
REQUIRE_UNRELEASED_VERSION=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  RESET=$'\033[0m'
else
  BOLD=''
  DIM=''
  GREEN=''
  RED=''
  YELLOW=''
  BLUE=''
  RESET=''
fi

PASS="${GREEN}✔${RESET}"
FAIL="${RED}✘${RESET}"
SKIP="${YELLOW}○${RESET}"
ARROW="${BLUE}▸${RESET}"

TOTAL=0
PASSED=0
FAILED=0
FAILURES=()

now_ns() {
  local timestamp

  timestamp="$(date +%s%N)"
  if [[ "$timestamp" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$timestamp"
    return
  fi

  uv run python -c 'import time; print(time.monotonic_ns())'
}

START_TIME="$(now_ns)"

usage() {
  cat <<'USAGE'
Usage: scripts/preflight-checks.sh [options]

Runs the local gruff-py preflight suite:
  - bash syntax check for scripts/*.sh
  - shellcheck for scripts/*.sh when shellcheck is installed
  - version agreement check for pyproject.toml and src/gruffpy/version.py
  - dependency vulnerability audit
  - ruff lint and format checks
  - mypy type checking
  - generated rule docs check
  - gruff-py self-check (analyse src tests --fail-on advisory)
  - pytest
  - uv build

Options:
  --skip-build        Skip uv build.
  --require-unreleased-version
                      Fail if the current version already has a local
                      release tag (v<version> or <version>).
  -h, --help          Show this help.
USAGE
}

rule() {
  printf '  %s\n' "${DIM}────────────────────────────────────────────${RESET}"
}

elapsed_since() {
  local started_at=$1
  local finished_at
  local elapsed_ms
  local seconds
  local minutes
  local remainder
  local frac

  finished_at="$(now_ns)"
  elapsed_ms=$(((finished_at - started_at) / 1000000))

  if ((elapsed_ms < 1000)); then
    printf '%dms' "$elapsed_ms"
    return
  fi

  seconds=$((elapsed_ms / 1000))
  frac=$(((elapsed_ms % 1000) / 100))

  if ((seconds < 60)); then
    printf '%d.%ds' "$seconds" "$frac"
    return
  fi

  minutes=$((seconds / 60))
  remainder=$((seconds % 60))
  printf '%dm %02d.%ds' "$minutes" "$remainder" "$frac"
}

header() {
  printf '\n'
  printf '  %sPreflight Check%s\n' "$BOLD" "$RESET"
  printf '  %s%s%s\n' "$DIM" "$(date '+%Y-%m-%d %H:%M:%S')" "$RESET"
  rule
  printf '\n'
}

step() {
  local label=$1

  TOTAL=$((TOTAL + 1))
  printf '  %s %-40s' "$ARROW" "$label"
}

pass() {
  local detail=${1:-}

  PASSED=$((PASSED + 1))
  if [[ -n "$detail" ]]; then
    printf '%s  %s%s%s\n' "$PASS" "$DIM" "$detail" "$RESET"
  else
    printf '%s\n' "$PASS"
  fi
}

fail() {
  local label=$1

  FAILED=$((FAILED + 1))
  FAILURES+=("$label")
  printf '%s\n' "$FAIL"
}

skip() {
  local reason=${1:-skipped}

  printf '%s  %s%s%s\n' "$SKIP" "$DIM" "$reason" "$RESET"
}

indent_output() {
  while IFS= read -r line; do
    printf '    %s%s%s\n' "$DIM" "$line" "$RESET"
  done
}

run_step() {
  local label=$1
  shift
  local started_at
  local output
  local status
  local elapsed

  step "$label"
  started_at="$(now_ns)"
  output=$("$@" 2>&1)
  status=$?
  elapsed="$(elapsed_since "$started_at")"

  if ((status == 0)); then
    pass "${output:+$output }$elapsed"
  else
    fail "$label"
    if [[ -n "$output" ]]; then
      printf '%s\n' "$output" | tail -20 | indent_output
    fi
    printf '    %sexit %d after %s%s\n' "$DIM" "$status" "$elapsed" "$RESET"
  fi

  return "$status"
}

command_check() {
  local command_name=$1

  command -v "$command_name" >/dev/null 2>&1
}

shell_script_paths() {
  find scripts -maxdepth 1 -type f -name '*.sh' | sort
}

bash_syntax_check() {
  local scripts=()
  mapfile -t scripts < <(shell_script_paths)

  if ((${#scripts[@]} == 0)); then
    printf 'no shell scripts found under scripts/'
    return 0
  fi

  bash -n "${scripts[@]}"
}

shellcheck_check() {
  local scripts=()
  mapfile -t scripts < <(shell_script_paths)

  if ((${#scripts[@]} == 0)); then
    printf 'no shell scripts found under scripts/'
    return 0
  fi

  shellcheck "${scripts[@]}"
}

version_check() {
  local output
  local version
  local existing_tags=()
  local tag

  output="$("$SCRIPT_DIR/bump-version.sh" --check 2>&1)" || {
    printf '%s\n' "$output"
    return 1
  }

  version="$(printf '%s\n' "$output" | awk '/versions agree:/ {print $NF; exit}')"
  if [[ -z "$version" ]]; then
    printf 'Could not read agreed version from scripts/bump-version.sh --check output.\n'
    printf '%s\n' "$output"
    return 1
  fi

  if ((REQUIRE_UNRELEASED_VERSION)); then
    if ! command_check git; then
      printf 'git is not available on PATH; cannot check release tags.\n'
      return 127
    fi

    for tag in "v${version}" "$version"; do
      if git -C "$ROOT_DIR" rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
        existing_tags+=("$tag")
      fi
    done

    if ((${#existing_tags[@]} > 0)); then
      printf 'version %s already has local release tag(s): %s\n' "$version" "${existing_tags[*]}"
      printf 'Run: scripts/bump-version.sh <new-version>\n'
      return 1
    fi

    printf 'version: %s, no local release tag' "$version"
    return 0
  fi

  printf 'version: %s' "$version"
}

dependency_audit_check() {
  local output
  local status
  local summary

  output="$(uv run pip-audit --skip-editable --progress-spinner off 2>&1)"
  status=$?

  if ((status == 0)); then
    summary="$(printf '%s\n' "$output" | grep -E '^No known vulnerabilities found' | tail -1 || true)"
    printf '%s' "${summary:-$output}"
  else
    printf '%s\n' "$output"
  fi

  return "$status"
}

ruff_lint_check() {
  uv run ruff check src tests
}

ruff_format_check() {
  uv run ruff format --check src tests
}

mypy_check() {
  uv run mypy src
}

rule_docs_check() {
  uv run python -m gruffpy.command.rule_docs --check docs/rules.md
}

gruff_py_self_check() {
  local output
  local status
  local findings

  output="$(uv run gruff-py analyse src tests --fail-on advisory --format text 2>&1)"
  status=$?
  findings="$(printf '%s\n' "$output" | awk '/^  Findings:/ {sub(/^  Findings: /, ""); print; exit}')"

  if ((status == 0)); then
    printf 'findings: %s' "${findings:-0}"
  else
    printf '%s\n' "$output"
  fi

  return "$status"
}

pytest_check() {
  local output
  local status
  local summary

  output="$(uv run pytest 2>&1)"
  status=$?

  if ((status == 0)); then
    summary="$(printf '%s\n' "$output" | grep -E '[0-9]+ passed' | tail -1 || true)"
    printf '%s' "${summary:-passed}"
  else
    printf '%s\n' "$output"
  fi

  return "$status"
}

package_build_check() {
  local output
  local status

  output="$(uv build 2>&1)"
  status=$?

  if ((status == 0)); then
    printf '%s' "$(printf '%s\n' "$output" | awk '/^Successfully built / {sub(/^Successfully built /, ""); items = items ? items ", " $0 : $0} END {print items}')"
  else
    printf '%s\n' "$output"
  fi

  return "$status"
}

summary() {
  local elapsed

  elapsed="$(elapsed_since "$START_TIME")"
  printf '\n'
  rule
  printf '\n'

  if ((FAILED == 0)); then
    printf '  %sAll %d/%d checks passed%s  %s(%s)%s\n' "$GREEN$BOLD" "$PASSED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
    printf '\n'
    return 0
  fi

  printf '  %s%d/%d checks failed%s  %s(%s)%s\n' "$RED$BOLD" "$FAILED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
  printf '\n'
  for failure in "${FAILURES[@]}"; do
    printf '    %s  %s\n' "$FAIL" "$failure"
  done
  printf '\n'

  return 1
}

main() {
  local bash_status=0
  local shellcheck_status=0
  local version_status=0
  local dependency_audit_status=0
  local ruff_lint_status=0
  local ruff_format_status=0
  local mypy_status=0
  local rule_docs_status=0
  local gruff_py_status=0
  local pytest_status=0
  local build_status=0
  local summary_status=0

  while (($#)); do
    case "$1" in
      --skip-build)
        RUN_BUILD=0
        ;;
      --require-unreleased-version)
        REQUIRE_UNRELEASED_VERSION=1
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        printf '%sUnknown option:%s %s\n' "$RED" "$RESET" "$1" >&2
        usage >&2
        return 64
        ;;
    esac

    shift
  done

  cd "$ROOT_DIR" || return 1

  header

  if ! command_check uv; then
    step "uv"
    fail "uv"
    printf '    %suv is not available on PATH.%s\n' "$DIM" "$RESET"
    summary
    return 127
  fi

  run_step "Bash syntax" bash_syntax_check
  bash_status=$?

  if command_check shellcheck; then
    run_step "Shellcheck" shellcheck_check
    shellcheck_status=$?
  else
    step "Shellcheck"
    skip "not installed"
  fi

  run_step "Version" version_check
  version_status=$?

  run_step "Dependency audit" dependency_audit_check
  dependency_audit_status=$?

  run_step "Ruff lint" ruff_lint_check
  ruff_lint_status=$?

  run_step "Ruff format" ruff_format_check
  ruff_format_status=$?

  run_step "Mypy" mypy_check
  mypy_status=$?

  run_step "Rule docs" rule_docs_check
  rule_docs_status=$?

  run_step "Gruff self-check" gruff_py_self_check
  gruff_py_status=$?

  run_step "Tests" pytest_check
  pytest_status=$?

  if ((RUN_BUILD)); then
    run_step "Package build" package_build_check
    build_status=$?
  else
    step "Package build"
    skip "--skip-build"
  fi

  summary
  summary_status=$?

  if ((
    bash_status != 0 ||
    shellcheck_status != 0 ||
    version_status != 0 ||
    dependency_audit_status != 0 ||
    ruff_lint_status != 0 ||
    ruff_format_status != 0 ||
    mypy_status != 0 ||
    rule_docs_status != 0 ||
    gruff_py_status != 0 ||
    pytest_status != 0 ||
    build_status != 0
  )); then
    return 1
  fi

  return "$summary_status"
}

main "$@"
