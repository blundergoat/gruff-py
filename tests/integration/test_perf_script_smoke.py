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


def test_perf_script_quick_mode_smoke(tmp_path: Path) -> None:
    json_out = tmp_path / "perf-results.json"
    output_dir = tmp_path / "perf-out"

    proc = subprocess.run(
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

    assert proc.returncode == 0, (
        f"perf script exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert json_out.exists(), "expected JSON output file was not written"

    payload = json.loads(json_out.read_text())
    assert payload["schemaVersion"] == 1
    for key in ("host", "repeat", "workloads", "perRuleCost", "importTime", "regressions"):
        assert key in payload, f"missing top-level key: {key}"

    workload_names = {w["name"] for w in payload["workloads"]}
    assert {"cold-start", "analyse-src-text"}.issubset(workload_names)

    for workload in payload["workloads"]:
        assert isinstance(workload["command"], list)
        assert isinstance(workload["exitCode"], int)
        assert workload["median"] > 0
        assert workload["min"] <= workload["median"] <= workload["max"]

    cold_start = next(w for w in payload["workloads"] if w["name"] == "cold-start")
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


def test_perf_script_help_lists_documented_flags() -> None:
    proc = subprocess.run(
        ["bash", str(SCRIPT_PATH), "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    for flag in (
        "--quick",
        "--json",
        "--repeat",
        "--baseline",
        "--update-baseline",
        "--output-dir",
        "--scale",
    ):
        assert flag in proc.stdout, f"--help output missing {flag}"
