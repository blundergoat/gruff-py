#!/usr/bin/env bash
# scripts/test-performance.sh - gruff-py performance harness.
#
# Measures wall-clock, peak RSS, per-rule cost attribution, and scaling
# behaviour across a fixed workload matrix. Emits human-readable output by
# default and a machine-readable JSON document on --json.
#
# Read-only against the source tree. All intermediate artifacts go to
# --output-dir (default ./perf-out/, gitignored).
#
# Subcommands / flags:
#   (default)                run the full suite, print summary, exit 0
#   --quick                  cold-start + analyse-src only (CI smoke)
#   --json [PATH]            also write JSON results (default perf-out/perf-results.json)
#   --repeat N               measurements per workload (default 5, min 3)
#   --baseline PATH          compare median wall-clock vs PATH; exit 1 on regression
#   --update-baseline PATH   overwrite PATH with current results and exit 0
#   --output-dir DIR         where to put artifacts (default ./perf-out/)
#   --scale large            include synthetic-10000 workload (default skips it)
#   --help                   this help
#
# Regression thresholds (env-overridable):
#   PERF_REGRESSION_PCT      default 20  (per-workload median % regression)
#   PERF_REGRESSION_ABS_S    default 0.5 (per-workload median absolute seconds)
# A workload regresses if BOTH limits are exceeded.
#
# Exit codes: 0 clean, 1 regression detected, 2 script error.

set -euo pipefail

# --- defaults ----------------------------------------------------------------
QUICK=0
EMIT_JSON=0
JSON_PATH=""
REPEAT=5
BASELINE_PATH=""
UPDATE_BASELINE_PATH=""
OUTPUT_DIR="./perf-out"
SCALE="small"

REGRESSION_PCT="${PERF_REGRESSION_PCT:-20}"
REGRESSION_ABS_S="${PERF_REGRESSION_ABS_S:-0.5}"

# --- arg parsing -------------------------------------------------------------
usage() {
  awk 'NR == 1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) QUICK=1; shift ;;
    --json)
      EMIT_JSON=1
      if [[ $# -gt 1 && "$2" != --* ]]; then JSON_PATH="$2"; shift 2
      else shift; fi ;;
    --repeat) REPEAT="$2"; shift 2 ;;
    --baseline) BASELINE_PATH="$2"; shift 2 ;;
    --update-baseline) UPDATE_BASELINE_PATH="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --scale) SCALE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if (( REPEAT < 3 )); then
  echo "error: --repeat must be >= 3 (got $REPEAT)" >&2
  exit 2
fi

if [[ -n "$BASELINE_PATH" && -n "$UPDATE_BASELINE_PATH" ]]; then
  echo "error: --baseline cannot be combined with --update-baseline" >&2
  exit 2
fi

if [[ -n "$BASELINE_PATH" && ! -f "$BASELINE_PATH" ]]; then
  echo "error: --baseline path does not exist: $BASELINE_PATH" >&2
  exit 2
fi

# --- environment probe -------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd)"
[[ -z "$JSON_PATH" ]] && JSON_PATH="$OUTPUT_DIR/perf-results.json"

PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
PYTHON_VERSION="$(uv run python -c 'import sys; print(".".join(str(x) for x in sys.version_info[:3]))')"
GRUFF_VERSION="$(uv run gruff-py --version 2>&1 | head -1 | awk '{print $2}')"

# Locate GNU time.
TIME_BIN=""
if [[ -x /usr/bin/time ]]; then
  if /usr/bin/time -v true >/dev/null 2>&1; then
    TIME_BIN="/usr/bin/time"
  fi
fi
if [[ -z "$TIME_BIN" ]] && command -v gtime >/dev/null 2>&1; then
  if gtime -v true >/dev/null 2>&1; then
    TIME_BIN="$(command -v gtime)"
  fi
fi
RSS_AVAILABLE=$([[ -n "$TIME_BIN" ]] && echo true || echo false)

# Synthetic fixture root (cleaned via trap).
SYNTHETIC_ROOT=""
# shellcheck disable=SC2317,SC2329  # invoked via trap
cleanup() {
  if [[ -n "$SYNTHETIC_ROOT" && -d "$SYNTHETIC_ROOT" ]]; then
    rm -rf "$SYNTHETIC_ROOT"
  fi
}
trap cleanup EXIT INT TERM

# --- helpers -----------------------------------------------------------------
# JSON string-escape helper using python -c (read-only).
json_escape() {
  uv run python -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

# JSON argv helper using python -c (read-only).
json_argv() {
  uv run python -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@"
}

date_has_fractional_seconds() {
  [[ "$(date +%s.%N)" =~ ^[0-9]+\.[0-9]+$ ]]
}

DATE_HAS_FRACTIONAL_SECONDS=0
if date_has_fractional_seconds; then
  DATE_HAS_FRACTIONAL_SECONDS=1
fi

now_seconds() {
  if [[ "$DATE_HAS_FRACTIONAL_SECONDS" == "1" ]]; then
    date +%s.%N
  else
    uv run python -c 'import time; print(f"{time.perf_counter():.9f}")'
  fi
}

# Compute median/p95/min/max/mean over a whitespace-separated list of floats.
# Outputs five floats on one line.
stats5() {
  uv run python - "$@" <<'PY'
import sys
xs = sorted(float(x) for x in sys.argv[1:])
n = len(xs)
median = xs[n//2] if n % 2 else (xs[n//2 - 1] + xs[n//2]) / 2
idx = max(0, min(n - 1, int(round(0.95 * (n - 1)))))
p95 = xs[idx]
mn, mx = xs[0], xs[-1]
mean = sum(xs) / n
print(f"{median:.4f} {p95:.4f} {mn:.4f} {mx:.4f} {mean:.4f}")
PY
}

# Run one workload N times. Echo space-separated wall times; capture peak RSS
# (kilobytes) from the final timed run when available, and preserve the first
# non-zero exit code from any repetition.
# $1 = label, rest = command tokens.
run_workload() {
  local label="$1"; shift
  local times=()
  local rss_kb=""
  local exit_code=0
  local last_log="$OUTPUT_DIR/last_${label}.time"

  for ((i = 1; i <= REPEAT; i++)); do
    local t_start t_end
    local cmd_status=0
    if [[ -n "$TIME_BIN" && $i -eq REPEAT ]]; then
      t_start="$(now_seconds)"
      set +e
      "$TIME_BIN" -v -o "$last_log" "$@" >/dev/null 2>&1
      cmd_status=$?
      set -e
      t_end="$(now_seconds)"
      rss_kb="$(awk -F': ' '/Maximum resident set size/ {print $2}' "$last_log" 2>/dev/null || true)"
    else
      t_start="$(now_seconds)"
      set +e
      "$@" >/dev/null 2>&1
      cmd_status=$?
      set -e
      t_end="$(now_seconds)"
    fi
    local dt
    dt="$(awk -v a="$t_start" -v b="$t_end" 'BEGIN{printf "%.4f", b - a}')"
    times+=("$dt")
    if [[ "$cmd_status" != "0" ]]; then
      exit_code="$cmd_status"
      break
    fi
  done

  echo "${times[*]}|$rss_kb|$exit_code"
}

# Build synthetic project of $1 files under $2.
generate_synthetic() {
  local n="$1" dest="$2"
  mkdir -p "$dest"
  uv run python - "$n" "$dest" <<'PY'
import os, random, sys
n = int(sys.argv[1])
dest = sys.argv[2]
random.seed(42 * n)
template = '''\"\"\"Synthetic module {idx}.\"\"\"

import os
import sys


class Widget{idx}:
    \"\"\"Synthetic widget {idx}.\"\"\"

    def __init__(self, value: int) -> None:
        self.value = value

    def doubled(self) -> int:
        return self.value * 2

    def labelled(self, prefix: str) -> str:
        return f"{{prefix}}-{{self.value}}"


def compute_{idx}(x: int) -> int:
    total = 0
    for i in range(x):
        if i % 2 == 0:
            total += i
        else:
            total -= i
    return total


def render_{idx}(items: list[int]) -> str:
    parts = []
    for item in items:
        parts.append(str(item))
    return ",".join(parts)
'''
for i in range(n):
    path = os.path.join(dest, f"module_{i:05d}.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(template.format(idx=i))
PY
}

# --- workload matrix ---------------------------------------------------------
# Each entry: "label|cmd tokens space-separated"
WORKLOADS_QUICK=(
  "cold-start|uv run gruff-py --version"
  "analyse-src-text|uv run gruff-py analyse --fail-on none src/"
)

WORKLOADS_FULL=(
  "cold-start|uv run gruff-py --version"
  "help|uv run gruff-py --help"
  "list-rules|uv run gruff-py list-rules --format json"
  "analyse-src-text|uv run gruff-py analyse --fail-on none src/"
  "analyse-src-json|uv run gruff-py analyse --fail-on none src/ --format json"
  "analyse-tests|uv run gruff-py analyse --fail-on none tests/"
  "analyse-both|uv run gruff-py analyse --fail-on none src/ tests/"
  "metric-calibration|uv run gruff-py metric-calibration src/"
  "summary|uv run gruff-py summary src/"
  "report-html|uv run gruff-py report --fail-on none src/ --format html"
)

# --- run ---------------------------------------------------------------------
START_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ "$QUICK" == "1" ]]; then
  WORKLOADS=("${WORKLOADS_QUICK[@]}")
else
  WORKLOADS=("${WORKLOADS_FULL[@]}")
fi

# Synthetic fixtures (full mode only).
if [[ "$QUICK" != "1" ]]; then
  SYNTHETIC_ROOT="$(mktemp -d -t gruff-perf.XXXXXX)"
  echo "Generating synthetic fixtures under $SYNTHETIC_ROOT ..."
  generate_synthetic 100  "$SYNTHETIC_ROOT/proj100"
  generate_synthetic 1000 "$SYNTHETIC_ROOT/proj1000"
  # Synthetic fixtures live under $TMPDIR, which is in gruff-py's default
  # ignored-directories list; use --include-ignored so the files are seen.
  WORKLOADS+=("synthetic-100|uv run gruff-py analyse --fail-on none --include-ignored $SYNTHETIC_ROOT/proj100")
  WORKLOADS+=("synthetic-1000|uv run gruff-py analyse --fail-on none --include-ignored $SYNTHETIC_ROOT/proj1000")
  if [[ "$SCALE" == "large" ]]; then
    generate_synthetic 10000 "$SYNTHETIC_ROOT/proj10000"
    WORKLOADS+=("synthetic-10000|uv run gruff-py analyse --fail-on none --include-ignored $SYNTHETIC_ROOT/proj10000")
  fi
fi

declare -a RESULT_LINES=()

echo
echo "gruff-py performance suite"
echo "  host: $PLATFORM, python $PYTHON_VERSION, gruff-py $GRUFF_VERSION"
echo "  repeat: $REPEAT, rss-via: $([[ -n "$TIME_BIN" ]] && echo "$TIME_BIN -v" || echo "unavailable")"
echo "  output-dir: $OUTPUT_DIR"
echo
printf "  %-22s %10s %10s %10s %12s %8s\n" "workload" "median" "p95" "min" "peak-rss" "status"
printf "  %-22s %10s %10s %10s %12s %8s\n" "--------" "------" "---" "---" "--------" "------"

# Warm-up: one untimed analyse-src run if applicable.
uv run gruff-py --version >/dev/null 2>&1 || true

for entry in "${WORKLOADS[@]}"; do
  label="${entry%%|*}"
  cmd="${entry#*|}"
  # shellcheck disable=SC2206
  cmd_tokens=($cmd)

  raw="$(run_workload "$label" "${cmd_tokens[@]}")"
  exit_code="${raw##*|}"
  without_exit="${raw%|*}"
  times_str="${without_exit%|*}"
  rss_kb="${without_exit##*|}"
  # shellcheck disable=SC2086
  read -r median p95 mn mx mean <<<"$(stats5 $times_str)"

  if [[ -n "$rss_kb" ]]; then
    rss_disp="$(awk -v k="$rss_kb" 'BEGIN{printf "%.1f MB", k/1024}')"
  else
    rss_disp="-"
  fi
  if [[ "$exit_code" == "0" ]]; then
    status_disp="ok"
  else
    status_disp="exit $exit_code"
  fi
  printf "  %-22s %9ss %9ss %9ss %12s %8s\n" "$label" "$median" "$p95" "$mn" "$rss_disp" "$status_disp"

  if [[ "$exit_code" != "0" ]]; then
    echo "error: workload '$label' failed with exit $exit_code" >&2
    exit 2
  fi

  # Stash a JSON-ready line.
  RESULT_LINES+=("{\"name\":$(json_escape "$label"),\"command\":$(json_argv "${cmd_tokens[@]}"),\"median\":$median,\"p95\":$p95,\"min\":$mn,\"max\":$mx,\"mean\":$mean,\"peakRssKb\":${rss_kb:-null},\"exitCode\":$exit_code}")
done

# --- per-rule attribution (full mode only) -----------------------------------
PROFILE_LINES_JSON="[]"
IMPORTTIME_JSON="{}"
if [[ "$QUICK" != "1" ]]; then
  echo
  echo "Capturing cProfile attribution for analyse-src ..."
  PROFILE_OUT="$OUTPUT_DIR/analyse-src.prof"
  uv run python -m cProfile -o "$PROFILE_OUT" -m gruffpy analyse --fail-on none src/ >/dev/null 2>&1 || true
  if [[ -f "$PROFILE_OUT" ]]; then
    PROFILE_LINES_JSON="$(uv run python - "$PROFILE_OUT" <<'PY'
import json, pstats, sys
p = pstats.Stats(sys.argv[1])
pillar = {}
modules = {}
for func, (cc, nc, tt, ct, callers) in p.stats.items():
    filename, lineno, name = func
    if "src/gruffpy/rule/" not in filename:
        continue
    rel = filename.split("src/gruffpy/rule/")[1]
    pillar_name = rel.split("/")[0] if "/" in rel else "_root"
    pillar[pillar_name] = pillar.get(pillar_name, 0.0) + tt
    modules[rel] = modules.get(rel, 0.0) + ct
out = {
    "byPillarMs": [
        {"pillar": k, "totalMs": round(v * 1000, 2)}
        for k, v in sorted(pillar.items(), key=lambda kv: -kv[1])
    ],
    "topModulesMs": [
        {"module": k, "cumulativeMs": round(v * 1000, 2)}
        for k, v in sorted(modules.items(), key=lambda kv: -kv[1])[:30]
    ],
}
print(json.dumps(out))
PY
)"
    echo
    echo "  per-rule cost (top 5 modules from cProfile):"
    uv run python - "$PROFILE_OUT" <<'PY'
import pstats, sys
p = pstats.Stats(sys.argv[1])
modules = {}
for func, (cc, nc, tt, ct, _callers) in p.stats.items():
    filename, lineno, name = func
    if "src/gruffpy/rule/" not in filename:
        continue
    rel = filename.split("src/gruffpy/rule/")[1]
    modules[rel] = modules.get(rel, 0.0) + ct
for i, (rel, secs) in enumerate(sorted(modules.items(), key=lambda kv: -kv[1])[:5], 1):
    print(f"    {i}. {rel:<55} {secs * 1000:7.1f} ms")
PY
  fi

  echo
  echo "Capturing -X importtime for cold-start ..."
  IMPORTTIME_LOG="$OUTPUT_DIR/importtime.log"
  uv run python -X importtime -m gruffpy --version 2>"$IMPORTTIME_LOG" >/dev/null || true
  if [[ -s "$IMPORTTIME_LOG" ]]; then
    IMPORTTIME_JSON="$(uv run python - "$IMPORTTIME_LOG" <<'PY'
import json, re, sys
total = 0
heaviest = []
with open(sys.argv[1]) as fh:
    for line in fh:
        m = re.match(r"import time:\s+(\d+)\s+\|\s+(\d+)\s+\|\s+(\S+)", line)
        if not m:
            continue
        self_us, cum_us, mod = int(m.group(1)), int(m.group(2)), m.group(3)
        heaviest.append((self_us, cum_us, mod))
        if mod == "gruffpy.cli":
            total = cum_us
heaviest.sort(key=lambda r: -r[0])
out = {
    "gruffpyCliCumulativeUs": total,
    "topSelfImportsUs": [
        {"module": mod, "selfUs": self_us, "cumulativeUs": cum_us}
        for self_us, cum_us, mod in heaviest[:10]
    ],
}
print(json.dumps(out))
PY
)"
  fi
fi

# --- regression check --------------------------------------------------------
REGRESSIONS_JSON="[]"
REGRESSED=0
RESULTS_JOINED="$(IFS=,; echo "${RESULT_LINES[*]}")"
if [[ -n "$BASELINE_PATH" ]]; then
  echo
  echo "Comparing to baseline: $BASELINE_PATH"
  REGRESSION_OUTPUT="$(uv run python - "$BASELINE_PATH" "$REGRESSION_PCT" "$REGRESSION_ABS_S" "$RESULTS_JOINED" <<'PY'
import json, sys
baseline_path = sys.argv[1]
pct = float(sys.argv[2]) / 100.0
abs_s = float(sys.argv[3])
current_json = sys.argv[4]
with open(baseline_path) as fh:
    base = json.load(fh)
base_by_name = {w["name"]: w for w in base.get("workloads", [])}
current = json.loads(f"[{current_json}]") if current_json else []
regressions = []
for w in current:
    b = base_by_name.get(w["name"])
    if not b:
        continue
    bm, cm = float(b["median"]), float(w["median"])
    delta = cm - bm
    denominator = max(bm, 0.001)
    if delta > abs_s and delta / denominator > pct:
        regressions.append({"name": w["name"], "baselineMedian": bm, "currentMedian": cm, "deltaSeconds": round(delta, 3), "deltaPct": round(100 * delta / denominator, 1)})
print(json.dumps(regressions))
PY
)"
  REGRESSIONS_JSON="$REGRESSION_OUTPUT"
  if [[ "$REGRESSIONS_JSON" != "[]" ]]; then
    REGRESSED=1
    echo "  regressions detected:"
    uv run python -c "import json,sys; rs=json.loads(sys.argv[1]); [print(f\"    {r['name']}: {r['baselineMedian']:.3f}s -> {r['currentMedian']:.3f}s (+{r['deltaPct']}%)\") for r in rs]" "$REGRESSIONS_JSON"
  else
    echo "  no regressions."
  fi
fi

# --- JSON output -------------------------------------------------------------
JSON_DOC="$(cat <<EOF
{
  "schemaVersion": 1,
  "generatedAt": $(json_escape "$START_TS"),
  "host": {
    "platform": $(json_escape "$PLATFORM"),
    "python": $(json_escape "$PYTHON_VERSION"),
    "gruffPy": $(json_escape "$GRUFF_VERSION"),
    "rssAvailable": $RSS_AVAILABLE
  },
  "repeat": $REPEAT,
  "scale": $(json_escape "$SCALE"),
  "workloads": [${RESULTS_JOINED}],
  "perRuleCost": $PROFILE_LINES_JSON,
  "importTime": $IMPORTTIME_JSON,
  "regressions": $REGRESSIONS_JSON
}
EOF
)"

if [[ "$EMIT_JSON" == "1" || -n "$UPDATE_BASELINE_PATH" ]]; then
  echo "$JSON_DOC" > "$JSON_PATH"
  echo
  echo "JSON written: $JSON_PATH"
fi

if [[ -n "$UPDATE_BASELINE_PATH" ]]; then
  cp "$JSON_PATH" "$UPDATE_BASELINE_PATH"
  echo "Baseline updated: $UPDATE_BASELINE_PATH"
  exit 0
fi

if [[ "$REGRESSED" == "1" ]]; then
  exit 1
fi
exit 0
