import json
from pathlib import Path

from gruff.command.metric_calibration import (
    build_metric_calibration_report,
    metric_calibration_payload,
    render_metric_calibration_text,
)


def test_metric_calibration_report_summarises_function_metrics(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(
        "\n".join(
            [
                "def simple(value):",
                "    return value",
                "",
                "def branchy(value):",
                "    if value > 0 and value < 10:",
                "        return value + 1",
                "    return value - 1",
            ]
        )
        + "\n"
    )

    report = build_metric_calibration_report(
        paths=("src",),
        config_path=None,
        no_config=True,
        include_ignored=False,
        project_root=tmp_path,
    )
    payload = metric_calibration_payload(report, top=1)

    assert report.files_discovered == 1
    assert report.files_parsed == 1
    assert report.function_count == 2
    assert report.has_input_errors() is False

    metrics = {metric["name"]: metric for metric in payload["metrics"]}  # type: ignore[index]
    assert metrics["cyclomatic"]["min"] == 1
    assert metrics["cyclomatic"]["p50"] == 2
    assert metrics["cyclomatic"]["max"] == 3
    assert metrics["npath"]["count"] == 2
    assert metrics["halsteadVolume"]["warningThreshold"] == 180
    assert metrics["maintainabilityIndex"]["thresholdDirection"] == "below"

    top = payload["top"]  # type: ignore[index]
    assert top["cyclomatic"][0]["symbol"] == "branchy"  # type: ignore[index]


def test_metric_calibration_text_is_human_readable(tmp_path: Path) -> None:
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
    assert "Top cyclomatic:" in rendered
    assert "src/sample.py:1 only cyclomatic=1" in rendered


def test_metric_calibration_payload_is_json_serialisable(tmp_path: Path) -> None:
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

    assert "gruff.metric-calibration.v1" in encoded
