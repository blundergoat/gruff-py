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
REQUIRE_UNPUBLISHED_PYPI=0

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
  - documentation drift (README.md and docs/ agree with list-rules, cite only carried decisions, link only to real pages)
  - documentation drift fixtures (each mutation class is rejected: false-empty, phantom rule, decision-namespace, source-revision, dead link)
  - gruff-py self-check (analyse src tests --fail-on advisory)
  - pytest
  - uv build

Options:
  --skip-build        Skip uv build.
  --require-unreleased-version
                      Fail if the current version already has a local
                      release tag (v<version> or <version>).
  --require-unpublished-pypi
                      Fail if the current version already exists on PyPI.
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

version_exists_on_pypi() {
  local version=$1

  uv run python - "$version" <<'PY'
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

version = sys.argv[1]
try:
    with urlopen("https://pypi.org/pypi/gruff-py/json", timeout=10) as response:
        payload = json.load(response)
except HTTPError as exc:
    print(f"Could not query PyPI release metadata: HTTP {exc.code}")
    raise SystemExit(2) from exc
except URLError as exc:
    print(f"Could not query PyPI release metadata: {exc.reason}")
    raise SystemExit(2) from exc
except TimeoutError as exc:
    print("Could not query PyPI release metadata: timed out")
    raise SystemExit(2) from exc

raise SystemExit(0 if version in payload.get("releases", {}) else 1)
PY
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

  if ((REQUIRE_UNPUBLISHED_PYPI)); then
    local pypi_status
    local pypi_output

    pypi_output="$(version_exists_on_pypi "$version" 2>&1)"
    pypi_status=$?
    if ((pypi_status == 0)); then
      printf 'version %s already exists on PyPI\n' "$version"
      printf 'Run: scripts/bump-version.sh <new-version>\n'
      return 1
    fi
    if ((pypi_status != 1)); then
      printf '%s\n' "$pypi_output"
      return "$pypi_status"
    fi

    printf 'version: %s, not published on PyPI' "$version"
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

  output="$(uv run gruff-py analyse src tests --no-baseline --fail-on advisory --format text 2>&1)"
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

# ---------------------------------------------------------------------------
# Documentation drift (M09 task 14). The owned documentation must agree with the
# live rule catalogue, name only rules that ship, cite only decisions this port
# carries, and link only to pages that exist. Every extraction fails closed: a
# document that states no catalogue size or names no rule is a defect, not a pass.
# ---------------------------------------------------------------------------

# Extract the live catalogue facts once so every drift assertion reads one snapshot.
docs_drift_facts() {
  local catalogue_file=$1
  uv run python - "$catalogue_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    listing = json.load(handle)
rules = listing.get("rules") if isinstance(listing, dict) else None
if not rules:
    raise SystemExit("false-empty: list-rules published no rules under rules")
ids = sorted(rule["id"] for rule in rules)
pillars = sorted({rule["pillar"] for rule in rules})
print("count=" + str(len(rules)))
print("pillars=" + str(len(pillars)))
print("pillarNames=" + "|".join(pillars))
print("ids=" + " ".join(ids))
PY
}

# Read one fact from the extracted facts block.
docs_fact() {
  local facts=$1
  local key=$2
  sed -n "s/^${key}=//p" <<<"$facts"
}

# Capture the live catalogue facts, or the reason the catalogue could not be read.
docs_drift_live_facts() {
  local catalogue
  local facts
  local status

  catalogue=$(mktemp "${TMPDIR:-/tmp}/gruff-py-docs-drift.XXXXXX.json") || return 1
  if ! uv run gruff-py list-rules --format json >"$catalogue" 2>/dev/null; then
    rm -f -- "$catalogue"
    printf 'docs drift: list-rules --format json failed'
    return 1
  fi
  facts=$(docs_drift_facts "$catalogue" 2>&1)
  status=$?
  rm -f -- "$catalogue"
  printf '%s' "$facts"
  return "$status"
}

# Compare the owned documentation under one root with the live catalogue facts. Runs against the
# real checkout, and against synthetic copies in the fixture harness, so both share one contract.
docs_drift_check_root() {
  local docs_root=$1
  local facts=$2
  local readme="$docs_root/README.md"
  local rules_doc="$docs_root/docs/rules.md"
  local count pillars ids pillar_names
  local claim claims=0 doc token decision link
  local documents=() mentioned=() phantom=() bad_decisions=() dead=()

  count=$(docs_fact "$facts" count)
  pillars=$(docs_fact "$facts" pillars)
  ids=" $(docs_fact "$facts" ids) "
  pillar_names=$(docs_fact "$facts" pillarNames)

  for doc in "$readme" "$rules_doc"; do
    if [[ ! -f "$doc" ]]; then
      printf 'docs drift: false-empty: %s is missing\n' "${doc#"$docs_root"/}"
      return 1
    fi
  done

  # Source-revision claims: every stated catalogue size must equal the live catalogue.
  while IFS= read -r claim; do
    claims=$((claims + 1))
    if [[ "$claim" != "registers $count rules across $pillars pillars" ]]; then
      printf 'docs drift: source-revision: docs/rules.md says "%s" but list-rules has %s rules across %s pillars\n' \
        "$claim" "$count" "$pillars"
      return 1
    fi
  done < <(grep -oE 'registers [0-9]+ rules across [0-9]+ pillars' "$rules_doc")
  if ((claims == 0)); then
    printf 'docs drift: false-empty: docs/rules.md states no catalogue size\n'
    return 1
  fi

  # Phantom rule ids: a backticked <pillar>.<slug> in the README or docs must be a rule that
  # ships. UPGRADING.md is history by design, and a line that says retired or removed is too.
  mapfile -t documents < <(find "$docs_root/docs" -maxdepth 1 -name '*.md' 2>/dev/null | sort)
  documents+=("$readme")
  while IFS= read -r token; do
    mentioned+=("$token")
    if [[ "$ids" != *" $token "* ]]; then
      phantom+=("$token")
    fi
  done < <(grep -hvE 'retired|removed' "${documents[@]}" \
    | grep -oE "\`($pillar_names)\.[a-z0-9-]+\`" | tr -d '`' | sort -u)
  if ((${#mentioned[@]} == 0)); then
    printf 'docs drift: false-empty: the documentation names no rule id\n'
    return 1
  fi
  if ((${#phantom[@]} > 0)); then
    printf 'docs drift: phantom rule ids not in list-rules: %s\n' "${phantom[*]}"
    return 1
  fi

  # Decision namespace: every ADR the documentation cites must exist in this port's decisions.
  while IFS= read -r decision; do
    if ! compgen -G "$ROOT_DIR/.goat-flow/learning-loop/decisions/$decision-*.md" >/dev/null; then
      bad_decisions+=("$decision")
    fi
  done < <(cat "${documents[@]}" "$docs_root/UPGRADING.md" 2>/dev/null | grep -oE 'ADR-[0-9]{3}' | sort -u)
  if ((${#bad_decisions[@]} > 0)); then
    printf 'docs drift: decision-namespace: %s cited but absent from .goat-flow/learning-loop/decisions\n' \
      "${bad_decisions[*]}"
    return 1
  fi

  # Entry-page links: every relative link from the README must resolve inside the checkout. A
  # fixture copy carries only the documentation, so a link to any other checked-in file still
  # resolves against the real repository root.
  while IFS= read -r link; do
    if [[ ! -e "$docs_root/$link" && ! -e "$ROOT_DIR/$link" ]]; then
      dead+=("$link")
    fi
  done < <(grep -oE '\]\([^)#[:space:]]+' "$readme" | sed 's/^](//' | grep -vE '^(https?://|mailto:)' | sort -u)
  if ((${#dead[@]} > 0)); then
    printf 'docs drift: entry-page link does not resolve: %s\n' "${dead[*]}"
    return 1
  fi

  printf '%s rules, %s pillars; %s rule ids and every cited decision resolve' \
    "$count" "$pillars" "${#mentioned[@]}"
}

docs_drift_check() {
  local facts
  local status

  facts=$(docs_drift_live_facts)
  status=$?
  if ((status != 0)); then
    printf '%s' "$facts"
    return "$status"
  fi
  docs_drift_check_root "$ROOT_DIR" "$facts"
}

# Run the drift check against one mutated copy and require the named rejection.
expect_docs_drift_rejection() {
  local case_name=$1
  local expected=$2
  local docs_root=$3
  local facts=$4
  local output

  if output=$(docs_drift_check_root "$docs_root" "$facts" 2>&1); then
    printf 'docs drift fixture %s: the mutation passed the gate\n' "$case_name"
    return 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    printf 'docs drift fixture %s: rejected for the wrong reason; expected "%s", got: %s\n' \
      "$case_name" "$expected" "$output"
    return 1
  fi
}

# Prove the drift gate rejects each mutation class without touching the real documentation
# (M09 task 16): false-empty, phantom rule, decision-namespace, source-revision, dead link.
docs_drift_fixture_check() {
  local facts status harness valid root count first_pillar
  local backtick='`'

  facts=$(docs_drift_live_facts)
  status=$?
  if ((status != 0)); then
    printf '%s' "$facts"
    return "$status"
  fi
  count=$(docs_fact "$facts" count)
  first_pillar=$(docs_fact "$facts" pillarNames)
  first_pillar=${first_pillar%%|*}

  harness=$(mktemp -d "${TMPDIR:-/tmp}/gruff-py-docs-fixtures.XXXXXX") || return 1
  valid="$harness/valid"
  mkdir -p "$valid"
  cp "$ROOT_DIR/README.md" "$ROOT_DIR/UPGRADING.md" "$valid/"
  cp -R "$ROOT_DIR/docs" "$valid/docs"
  if ! docs_drift_check_root "$valid" "$facts" >/dev/null 2>&1; then
    printf 'docs drift fixture: the unmodified copy failed the gate'
    rm -rf -- "$harness"
    return 1
  fi

  root="$harness/false-empty"
  cp -R "$valid" "$root"
  printf '# gruff-py\n\nSee the docs.\n' >"$root/README.md"
  printf '# Rules\n\nSee list-rules.\n' >"$root/docs/rules.md"
  expect_docs_drift_rejection false-empty 'false-empty' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  root="$harness/phantom-rule"
  cp -R "$valid" "$root"
  printf '\nThe %s%s.phantom-rule%s rule is documented here.\n' "$backtick" "$first_pillar" "$backtick" >>"$root/README.md"
  expect_docs_drift_rejection phantom-rule 'phantom rule ids' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  root="$harness/decision-namespace"
  cp -R "$valid" "$root"
  printf '\nSee ADR-999 for the rationale.\n' >>"$root/README.md"
  expect_docs_drift_rejection decision-namespace 'decision-namespace' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  root="$harness/source-revision"
  cp -R "$valid" "$root"
  sed -i "s/registers $count rules across/registers $((count + 1)) rules across/" "$root/docs/rules.md"
  expect_docs_drift_rejection source-revision 'source-revision' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  root="$harness/dead-link"
  cp -R "$valid" "$root"
  printf '\n[Missing page](docs/missing-page.md)\n' >>"$root/README.md"
  expect_docs_drift_rejection dead-link 'entry-page link' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

  rm -rf -- "$harness"
  printf '5 mutations rejected'
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
  local docs_drift_status=0
  local docs_drift_fixture_status=0
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
      --require-unpublished-pypi)
        REQUIRE_UNPUBLISHED_PYPI=1
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

  run_step "Documentation drift" docs_drift_check
  docs_drift_status=$?

  run_step "Documentation drift fixtures" docs_drift_fixture_check
  docs_drift_fixture_status=$?

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
    docs_drift_status != 0 ||
    docs_drift_fixture_status != 0 ||
    gruff_py_status != 0 ||
    pytest_status != 0 ||
    build_status != 0
  )); then
    return 1
  fi

  return "$summary_status"
}

main "$@"
