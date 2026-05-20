#!/usr/bin/env bash
# scripts/preflight-checks.sh - gruff-py local preflight gate.
#
# Runs Python static checks, docs checks, gruff-py summary, tests, package
# build, and sibling gruff-go checks. Build artifacts are written under
# dist/, which is gitignored in this project.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
GRUFF_GO_DIR="${GRUFF_GO_DIR:-"$ROOT_DIR/../gruff-go"}"
RUN_GRUFF_GO=1
RUN_BUILD=1

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
  - ruff lint and format checks
  - mypy type checking
  - generated rule docs check
  - gruff-py summary check
  - pytest
  - uv build
  - sibling gruff-go gofmt/go vet/go test/dogfood checks

Options:
  --skip-gruff-go     Skip sibling gruff-go checks.
  --gruff-go-dir DIR  Run gruff-go checks in DIR (default: ../gruff-go).
  --skip-build        Skip uv build.
  -h, --help          Show this help.

Environment:
  GRUFF_GO_DIR        Override sibling gruff-go directory.
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

run_step_in() {
  local dir=$1
  local label=$2
  shift 2
  local started_at
  local output
  local status
  local elapsed

  step "$label"
  started_at="$(now_ns)"
  output=$(cd "$dir" && "$@" 2>&1)
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
  uv run python -m gruffpy.command.rule_docs --check docs/RULES.md
}

gruff_py_summary_check() {
  local output
  local status
  local findings
  local files

  output="$(uv run gruff-py summary --format text --top 5 src/ 2>&1)"
  status=$?

  if ((status == 0)); then
    files="$(printf '%s\n' "$output" | awk -F': ' '/^Files:/ {print $2; exit}')"
    findings="$(printf '%s\n' "$output" | awk -F': ' '/^Findings:/ {print $2; exit}')"
    printf '%s findings; %s' "${findings:-unknown}" "${files:-file summary unavailable}"
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

go_package_files() {
  local go_list_template

  go_list_template='{{range .GoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .TestGoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .XTestGoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}'
  go list -f "$go_list_template" ./...
}

gruff_go_format_check() {
  local go_files=()
  local file_list
  local unformatted=()

  file_list="$(go_package_files)"
  while IFS= read -r go_file; do
    [[ -n "$go_file" ]] && go_files+=("$go_file")
  done <<<"$file_list"

  if ((${#go_files[@]} == 0)); then
    printf 'no Go package files found'
    return 0
  fi

  mapfile -t unformatted < <(gofmt -l "${go_files[@]}")
  if ((${#unformatted[@]} > 0)); then
    printf 'gofmt required for:\n'
    printf '  %s\n' "${unformatted[@]}"
    return 1
  fi

  printf '%d files' "${#go_files[@]}"
}

gruff_go_vet_check() {
  go vet ./...
}

gruff_go_test_check() {
  local output
  local status
  local packages

  output="$(go test ./... 2>&1)"
  status=$?

  if ((status == 0)); then
    packages="$(printf '%s\n' "$output" | grep -Ec '^(ok|\?)\s+' || true)"
    printf '%s packages' "${packages:-0}"
  else
    printf '%s\n' "$output"
  fi

  return "$status"
}

gruff_go_dogfood_check() {
  local output
  local status
  local findings
  local exit_line

  output="$(go run ./cmd/gruff-go analyse . 2>&1)"
  status=$?

  if ((status == 0)); then
    findings="$(printf '%s\n' "$output" | awk -F': ' '/^findings:/ {print $2; exit}')"
    exit_line="$(printf '%s\n' "$output" | awk -F': ' '/^exit:/ {print $2; exit}')"
    printf 'findings: %s, exit: %s' "${findings:-unknown}" "${exit_line:-unknown}"
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
  local ruff_lint_status=0
  local ruff_format_status=0
  local mypy_status=0
  local rule_docs_status=0
  local gruff_py_status=0
  local pytest_status=0
  local build_status=0
  local gruff_go_format_status=0
  local gruff_go_vet_status=0
  local gruff_go_test_status=0
  local gruff_go_dogfood_status=0
  local summary_status=0

  while (($#)); do
    case "$1" in
      --skip-gruff-go)
        RUN_GRUFF_GO=0
        ;;
      --gruff-go-dir)
        [[ $# -ge 2 ]] || {
          printf '%sMissing value for --gruff-go-dir%s\n' "$RED" "$RESET" >&2
          usage >&2
          return 64
        }
        GRUFF_GO_DIR="$2"
        shift
        ;;
      --skip-build)
        RUN_BUILD=0
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

  case "$GRUFF_GO_DIR" in
    /*) ;;
    *) GRUFF_GO_DIR="$ROOT_DIR/$GRUFF_GO_DIR" ;;
  esac

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

  run_step "Ruff lint" ruff_lint_check
  ruff_lint_status=$?

  run_step "Ruff format" ruff_format_check
  ruff_format_status=$?

  run_step "Mypy" mypy_check
  mypy_status=$?

  run_step "Rule docs" rule_docs_check
  rule_docs_status=$?

  run_step "Gruff summary" gruff_py_summary_check
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

  if ((RUN_GRUFF_GO)); then
    if [[ ! -d "$GRUFF_GO_DIR" ]]; then
      step "gruff-go checkout"
      fail "gruff-go checkout"
      printf '    %sMissing directory: %s%s\n' "$DIM" "$GRUFF_GO_DIR" "$RESET"
      gruff_go_format_status=1
    elif ! command_check go; then
      step "Go toolchain"
      fail "Go toolchain"
      printf '    %sgo is not available on PATH.%s\n' "$DIM" "$RESET"
      gruff_go_format_status=127
    else
      run_step_in "$GRUFF_GO_DIR" "gruff-go gofmt" gruff_go_format_check
      gruff_go_format_status=$?

      run_step_in "$GRUFF_GO_DIR" "gruff-go vet" gruff_go_vet_check
      gruff_go_vet_status=$?

      run_step_in "$GRUFF_GO_DIR" "gruff-go tests" gruff_go_test_check
      gruff_go_test_status=$?

      run_step_in "$GRUFF_GO_DIR" "gruff-go dogfood" gruff_go_dogfood_check
      gruff_go_dogfood_status=$?
    fi
  else
    step "gruff-go checks"
    skip "--skip-gruff-go"
  fi

  summary
  summary_status=$?

  if ((
    bash_status != 0 ||
    shellcheck_status != 0 ||
    ruff_lint_status != 0 ||
    ruff_format_status != 0 ||
    mypy_status != 0 ||
    rule_docs_status != 0 ||
    gruff_py_status != 0 ||
    pytest_status != 0 ||
    build_status != 0 ||
    gruff_go_format_status != 0 ||
    gruff_go_vet_status != 0 ||
    gruff_go_test_status != 0 ||
    gruff_go_dogfood_status != 0
  )); then
    return 1
  fi

  return "$summary_status"
}

main "$@"
