from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.scoring.score_calculator import ScoreCalculator

CORRELATED_STACK_FINDINGS = 4


def _correlated_stack() -> list[Finding]:
    """A god-function's real metric findings - long, cyclomatically and
    cognitively complex, deeply nested - all on one symbol and line, so the
    correlated-rule clustering bills them as one penalty."""
    return [
        _finding("size.function-length", pillar=Pillar.SIZE),
        _finding("complexity.cyclomatic", pillar=Pillar.COMPLEXITY),
        _finding("complexity.cognitive", pillar=Pillar.COMPLEXITY),
        _finding("complexity.nesting-depth", pillar=Pillar.COMPLEXITY),
    ]


def _finding(
    rule_id: str,
    *,
    pillar: Pillar,
    lines: int | None = None,
    symbol: str | None = "run",
    line: int | None = 1,
) -> Finding:
    metadata = {}
    if lines is not None:
        metadata["lines"] = lines
    return Finding(
        rule_id=rule_id,
        message=f"{rule_id} hit",
        file_path="x.py",
        line=line,
        severity=Severity.WARNING,
        pillar=pillar,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        symbol=symbol,
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


def test_correlated_size_complexity_stack_is_downweighted_for_file_score():
    report = ScoreCalculator().calculate(_correlated_stack())

    offender = report.top_offenders[0]
    assert offender.findings == CORRELATED_STACK_FINDINGS
    assert offender.penalty == 20.0
    assert offender.grade.score == 80.0


def test_correlated_size_complexity_stack_is_downweighted_for_composite_score():
    report = ScoreCalculator().calculate(_correlated_stack())

    # With the god-method composite retired, no synthetic design finding is
    # injected: the design pillar takes zero penalty and the real size/complexity
    # findings absorb the whole clustered weight, leaving the composite unchanged.
    assert report.composite.score == 98.4
    pillar_penalties = {pillar.pillar: pillar.penalty for pillar in report.pillars}
    assert pillar_penalties["size"] == 4.0
    assert pillar_penalties["complexity"] == 12.0
    assert pillar_penalties["design"] == 0.0


def test_correlated_downweighting_requires_same_symbol_and_line():
    findings = [
        _finding("size.function-length", pillar=Pillar.SIZE, symbol="left", line=1),
        _finding("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, symbol="right", line=1),
    ]

    report = ScoreCalculator().calculate(findings)

    offender = report.top_offenders[0]
    assert offender.penalty == 40.0
    assert offender.grade.score == 60.0
