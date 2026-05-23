import json

from gruffpy.analysis.baseline import BaselineStore, apply_baseline
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity


def test_baseline_store_writes_python_schema_and_finding_rows(tmp_path):
    finding = _finding()

    data = BaselineStore(tmp_path).write("baselines/gruff-baseline.json", [finding])

    baseline = json.loads((tmp_path / "baselines" / "gruff-baseline.json").read_text())
    assert data.path == "baselines/gruff-baseline.json"
    assert baseline["schemaVersion"] == "gruff-py.baseline.v1"
    assert baseline["findings"] == [
        {
            "fingerprint": finding.fingerprint(),
            "ruleId": "docs.example",
            "file": "src/example.py",
            "line": 12,
            "symbol": "example",
            "message": "Example finding.",
        }
    ]


def test_baseline_apply_accepts_sibling_entries_shape(tmp_path):
    finding = _finding()
    baseline_path = tmp_path / "gruff-baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schemaVersion": "gruff.baseline.v1",
                "entries": [
                    {
                        "fingerprint": finding.fingerprint(),
                        "ruleId": finding.rule_id,
                        "filePath": finding.file_path,
                        "line": finding.line,
                        "symbol": finding.symbol,
                        "message": finding.message,
                    }
                ],
            }
        )
    )

    result = apply_baseline(
        project_root=tmp_path,
        path="gruff-baseline.json",
        findings=[finding],
        source="explicit",
    )

    assert result.findings == []
    assert result.report.path == "gruff-baseline.json"
    assert result.report.suppressed_findings == 1
    assert result.report.total_entries == 1
    assert result.report.stale_entries == ()


def test_baseline_apply_requires_rule_and_file_match(tmp_path):
    finding = _finding()
    baseline_path = tmp_path / "gruff-baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schemaVersion": "gruff-py.baseline.v1",
                "findings": [
                    {
                        "fingerprint": finding.fingerprint(),
                        "ruleId": "docs.other",
                        "file": finding.file_path,
                        "line": finding.line,
                        "symbol": finding.symbol,
                        "message": finding.message,
                    }
                ],
            }
        )
    )

    result = apply_baseline(
        project_root=tmp_path,
        path="gruff-baseline.json",
        findings=[finding],
        source="explicit",
    )

    assert result.findings == [finding]
    assert result.report.suppressed_findings == 0
    assert len(result.report.stale_entries) == 1


def _finding() -> Finding:
    return Finding(
        rule_id="docs.example",
        message="Example finding.",
        file_path="src/example.py",
        line=12,
        severity=Severity.ADVISORY,
        pillar=Pillar.DOCUMENTATION,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        symbol="example",
    )
