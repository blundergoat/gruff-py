import json
from pathlib import Path

from gruffpy.command.metric_calibration import (
    build_metric_calibration_report,
    metric_calibration_payload,
    render_metric_calibration_text,
)

_TWO_FUNCTION_SAMPLE = (
    "def simple(value):\n    return value\n\ndef branchy(value):\n    if value > 0 and value < 10:\n        return value + 1\n    return value - 1\n"
)


def _two_function_report(tmp_path: Path):
    """Build a metric calibration report, with no config, over a project holding one simple and one branchy function.

    Args:
        tmp_path: Project root that receives ``src/sample.py``.

    Returns:
        The calibration report for the ``src`` folder.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(_TWO_FUNCTION_SAMPLE)
    return build_metric_calibration_report(
        paths=("src",),
        config_path=None,
        no_config=True,
        include_ignored=False,
        project_root=tmp_path,
    )


def test_metric_calibration_report_counts_files_and_functions(tmp_path: Path) -> None:
    """Count one discovered file, one parsed file and two functions, with no input errors.

    Args:
        tmp_path: Project root for the two-function report.
    """
    report = _two_function_report(tmp_path)
    assert (
        report.files_discovered,
        report.files_parsed,
        report.function_count,
        report.has_input_errors(),
    ) == (1, 1, 2, False)


def test_metric_calibration_payload_cyclomatic_distribution(tmp_path: Path) -> None:
    """Publish the cyclomatic minimum, median, 99th percentile and maximum for the two functions.

    Args:
        tmp_path: Project root whose two functions supply the cyclomatic values.
    """
    payload = metric_calibration_payload(_two_function_report(tmp_path), top=1)
    metrics = {m["name"]: m for m in payload["metrics"]}  # type: ignore[index]  # metric JSON
    cyclomatic = metrics["cyclomatic"]
    assert (cyclomatic["min"], cyclomatic["p50"], cyclomatic["p99"], cyclomatic["max"]) == (
        1,
        2,
        2.98,
        3,
    )


def test_metric_calibration_payload_collapses_single_threshold_rules(tmp_path: Path) -> None:
    """Publish Halstead volume with one error threshold of 400 and no separate warning or error threshold keys.

    Args:
        tmp_path: Project root whose report supplies the Halstead entry.
    """
    payload = metric_calibration_payload(_two_function_report(tmp_path), top=1)
    metrics = {m["name"]: m for m in payload["metrics"]}  # type: ignore[index]  # metric JSON
    hv = metrics["halsteadVolume"]
    assert hv["threshold"] == 400
    assert hv["thresholdSeverity"] == "error"
    assert "warningThreshold" not in hv
    assert "errorThreshold" not in hv


def test_metric_calibration_payload_maintainability_uses_below_direction(tmp_path: Path) -> None:
    """Publish the maintainability index with a ``below`` threshold direction.

    Args:
        tmp_path: Project root whose report supplies the maintainability entry.
    """
    payload = metric_calibration_payload(_two_function_report(tmp_path), top=1)
    metrics = {m["name"]: m for m in payload["metrics"]}  # type: ignore[index]  # metric JSON
    assert metrics["maintainabilityIndex"]["thresholdDirection"] == "below"


def test_metric_calibration_payload_top_cyclomatic_names_branchy(tmp_path: Path) -> None:
    """Name the branchy function first in the top cyclomatic list.

    Args:
        tmp_path: Project root whose branchy function must top the list.
    """
    payload = metric_calibration_payload(_two_function_report(tmp_path), top=1)
    top = payload["top"]  # type: ignore[index]  # metric JSON
    assert top["cyclomatic"][0]["symbol"] == "branchy"  # type: ignore[index]  # metric JSON


def test_metric_calibration_text_is_human_readable(tmp_path: Path) -> None:
    """Render the text report with its title, distribution and top-cyclomatic sections and the one function's location text.

    Args:
        tmp_path: Project root holding one single-return function.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def only():\n    return 1\n")

    report = build_metric_calibration_report(
        paths=("src",),
        config_path=None,
        no_config=True,
        include_ignored=False,
        project_root=tmp_path,
    )

    rendered = render_metric_calibration_text(report, top=1)

    assert "metric calibration" in rendered
    assert "Metric distributions:" in rendered
    assert "p99" in rendered
    assert "Top cyclomatic:" in rendered
    assert "src/sample.py:1 only cyclomatic=1" in rendered


def test_metric_calibration_payload_is_json_serialisable(tmp_path: Path) -> None:
    """Encode the calibration payload as JSON that carries its schema version.

    Args:
        tmp_path: Project root holding one single-return function.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def only():\n    return 1\n")

    report = build_metric_calibration_report(
        paths=("src",),
        config_path=None,
        no_config=True,
        include_ignored=False,
        project_root=tmp_path,
    )

    encoded = json.dumps(metric_calibration_payload(report, top=1))

    assert "gruff-py.metric-calibration.v1" in encoded
