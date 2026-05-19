"""Smoke test for ``scripts/test-performance.sh``.

Runs the script in --quick mode and asserts that it exits 0 and emits a
JSON document with the expected top-level keys. Skipped on non-Linux hosts
and when ``bash`` is unavailable.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "test-performance.sh"


pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="perf script smoke test is Linux-only"),
    pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH"),
]


def _run_perf_script_quick(json_out: Path, output_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "bash",
            str(SCRIPT_PATH),
            "--quick",
            "--repeat",
            "3",
            "--json",
            str(json_out),
            "--output-dir",
            str(output_dir),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=300,
        check=False,
    )


@pytest.fixture(scope="module")
def quick_run_payload(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """Run the perf script once at --quick mode and return its parsed JSON payload.

    Args:
        tmp_path_factory: Pytest-provided factory for module-scoped temp dirs.

    Returns:
        The parsed ``--json`` payload from a single ``--quick`` invocation.
    """
    tmp_path = tmp_path_factory.mktemp("perf_quick")
    json_out = tmp_path / "perf-results.json"
    proc = _run_perf_script_quick(json_out, tmp_path / "perf-out")
    assert proc.returncode == 0, (
        f"perf script exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert json_out.exists(), "expected JSON output file was not written"
    return json.loads(json_out.read_text())


_EXPECTED_TOP_LEVEL_KEYS = {
    "schemaVersion",
    "host",
    "repeat",
    "workloads",
    "perRuleCost",
    "importTime",
    "regressions",
}


def test_perf_script_payload_advertises_schema_version_1(
    quick_run_payload: dict[str, object],
) -> None:
    assert quick_run_payload["schemaVersion"] == 1


def test_perf_script_payload_publishes_documented_top_level_keys(
    quick_run_payload: dict[str, object],
) -> None:
    assert _EXPECTED_TOP_LEVEL_KEYS.issubset(quick_run_payload), (
        f"missing top-level keys: {_EXPECTED_TOP_LEVEL_KEYS - quick_run_payload.keys()}"
    )


def test_perf_script_payload_reports_cold_start_and_analyse_workloads(
    quick_run_payload: dict[str, object],
) -> None:
    workloads = quick_run_payload["workloads"]
    workload_names = {w["name"] for w in workloads}
    assert {"cold-start", "analyse-src-text"}.issubset(workload_names)


def test_perf_script_workloads_have_well_formed_timing_record(
    quick_run_payload: dict[str, object],
) -> None:
    workloads = quick_run_payload["workloads"]
    assert all(
        isinstance(w["command"], list)
        and isinstance(w["exitCode"], int)
        and w["median"] > 0
        and w["min"] <= w["median"] <= w["max"]
        for w in workloads
    ), workloads


def test_perf_script_cold_start_workload_exits_zero(
    quick_run_payload: dict[str, object],
) -> None:
    workloads = quick_run_payload["workloads"]
    cold_start = next(w for w in workloads if w["name"] == "cold-start")
    assert cold_start["exitCode"] == 0


def test_perf_script_baseline_regression_exits_one(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "workloads": [
                    {"name": "cold-start", "median": 0.001},
                    {"name": "analyse-src-text", "median": 0.001},
                ],
            }
        )
    )

    proc = subprocess.run(
        [
            "bash",
            str(SCRIPT_PATH),
            "--quick",
            "--repeat",
            "3",
            "--baseline",
            str(baseline),
            "--output-dir",
            str(tmp_path / "perf-out"),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PERF_REGRESSION_ABS_S": "0.001",
            "PERF_REGRESSION_PCT": "1",
        },
        timeout=300,
        check=False,
    )

    assert proc.returncode == 1, (
        f"expected regression exit 1\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "regressions detected" in proc.stdout


_DOCUMENTED_FLAGS = (
    "--quick",
    "--json",
    "--repeat",
    "--baseline",
    "--update-baseline",
    "--output-dir",
    "--scale",
)


def test_perf_script_help_lists_documented_flags() -> None:
    proc = subprocess.run(
        ["bash", str(SCRIPT_PATH), "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    missing = [flag for flag in _DOCUMENTED_FLAGS if flag not in proc.stdout]
    assert not missing, f"--help output missing flags: {missing}"
