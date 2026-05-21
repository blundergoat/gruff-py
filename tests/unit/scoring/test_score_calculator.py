from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.scoring.score_calculator import ScoreCalculator


def _finding(rule_id: str, *, pillar: Pillar, lines: int | None = None) -> Finding:
    metadata = {}
    if lines is not None:
        metadata["lines"] = lines
    return Finding(
        rule_id=rule_id,
        message=f"{rule_id} hit",
        file_path="x.py",
        line=1,
        severity=Severity.WARNING,
        pillar=pillar,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        metadata=metadata,
    )


def test_score_report_static_pillars_include_design_not_modernisation():
    report = ScoreCalculator().calculate([])
    pillars = [score.pillar for score in report.pillars]

    assert "design" in pillars
    assert "modernisation" not in pillars


def test_file_score_max_lines_uses_function_length_findings():
    expected_max_lines = 75
    findings = [
        _finding("size.function-length", pillar=Pillar.SIZE, lines=expected_max_lines),
        _finding("size.parameter-count", pillar=Pillar.SIZE, lines=999),
    ]

    report = ScoreCalculator().calculate(findings)

    assert report.top_offenders[0].max_lines == expected_max_lines
