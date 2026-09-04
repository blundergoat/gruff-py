from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.rule.catalog import catalog_definitions
from gruffpy.scoring.score_calculator import STATIC_PILLARS, ScoreCalculator

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
    severity: Severity = Severity.WARNING,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    metadata = {}
    if lines is not None:
        metadata["lines"] = lines
    return Finding(
        rule_id=rule_id,
        message=f"{rule_id} hit",
        file_path="x.py",
        line=line,
        severity=severity,
        pillar=pillar,
        tier=RuleTier.V01,
        confidence=confidence,
        symbol=symbol,
        metadata=metadata,
    )


def test_static_pillars_covers_every_catalog_pillar():
    """Guard: a new rule may not introduce a pillar STATIC_PILLARS does not name.

    An unnamed pillar joins the composite average only on runs where it has
    findings, so the divisor changes between runs and fixing the last finding
    in that pillar can lower the composite.
    """
    catalog_pillars = {definition.pillar.value for definition in catalog_definitions()}
    catalog_pillars.update(secondary.value for definition in catalog_definitions() for secondary in definition.secondary_pillars)

    assert catalog_pillars - set(STATIC_PILLARS) == set()


def test_score_report_grades_every_static_pillar_with_no_findings():
    report = ScoreCalculator().calculate([], 10)
    pillars = [score.pillar for score in report.pillars]

    assert pillars == list(STATIC_PILLARS)
    assert {"design", "modernisation", "correctness"} <= set(pillars)


def test_fixing_the_last_finding_in_a_pillar_cannot_lower_the_composite():
    """The divisor must not shrink when a pillar stops having findings.

    Before the fix this scored 80.18 (B) with a divisor of 11 and 79.00 (C)
    with a divisor of 10 - the user lost a grade band for fixing two findings.
    """
    noise = [
        _finding(f"{pillar}.noise", pillar=Pillar(pillar), confidence=Confidence.MEDIUM, severity=Severity.ADVISORY)
        for pillar in STATIC_PILLARS
        if pillar != "modernisation"
        for _ in range(7)
    ]
    modernisation = [_finding("modernisation.f-string-candidate", pillar=Pillar.MODERNISATION, severity=Severity.ADVISORY) for _ in range(2)]

    before = ScoreCalculator().calculate(noise + modernisation, 10)
    after = ScoreCalculator().calculate(noise, 10)

    assert len(after.pillars) == len(before.pillars)
    assert after.composite.score >= before.composite.score


def test_fixing_the_last_correctness_finding_cannot_lower_the_composite():
    noise = [
        _finding(f"{pillar}.noise", pillar=Pillar(pillar), confidence=Confidence.MEDIUM, severity=Severity.ADVISORY)
        for pillar in STATIC_PILLARS
        if pillar != "correctness"
        for _ in range(7)
    ]
    correctness = [_finding("correctness.unsafe-numeric-coercion", pillar=Pillar.CORRECTNESS, severity=Severity.ADVISORY) for _ in range(2)]

    before = ScoreCalculator().calculate(noise + correctness, 10)
    after = ScoreCalculator().calculate(noise, 10)

    assert len(after.pillars) == len(before.pillars)
    assert after.composite.score >= before.composite.score


def test_file_score_max_lines_uses_function_length_findings():
    expected_max_lines = 75
    findings = [
        _finding("size.function-length", pillar=Pillar.SIZE, lines=expected_max_lines),
        _finding("size.parameter-count", pillar=Pillar.SIZE, lines=999),
    ]

    report = ScoreCalculator().calculate(findings, 10)

    assert report.top_offenders[0].max_lines == expected_max_lines


def test_correlated_size_complexity_stack_is_downweighted_for_file_score():
    report = ScoreCalculator().calculate(_correlated_stack(), 10)

    offender = report.top_offenders[0]
    assert offender.findings == CORRELATED_STACK_FINDINGS
    assert offender.penalty == 4.0
    assert offender.grade.score == 51.22


def test_correlated_size_complexity_stack_is_downweighted_for_composite_score():
    report = ScoreCalculator().calculate(_correlated_stack(), 10)

    # With the god-method composite retired, no synthetic design finding is
    # injected: the design pillar takes zero weight and the real size/complexity
    # findings absorb the whole clustered weight. Over ten evaluated files the
    # ratified curve scores size 75.00 and complexity 62.50, and the other ten
    # pillars 100.00, so the composite is 1137.50 / 12.
    assert report.composite.score == 94.79
    pillar_penalties = {pillar.pillar: pillar.penalty for pillar in report.pillars}
    assert pillar_penalties["size"] == 1.0
    assert pillar_penalties["complexity"] == 3.0
    assert pillar_penalties["design"] == 0.0


def test_correlated_downweighting_requires_same_symbol():
    findings = [
        _finding("size.function-length", pillar=Pillar.SIZE, symbol="left", line=1),
        _finding("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, symbol="right", line=1),
    ]

    report = ScoreCalculator().calculate(findings, 10)

    offender = report.top_offenders[0]
    assert offender.penalty == 8.0
    assert offender.grade.score == 50.62


def test_correlated_downweighting_groups_decorated_function_across_lines():
    # size.function-length reports the decorator line and complexity rules the def
    # line, so the same decorated symbol lands on different lines; it must still
    # cluster into a single penalty rather than billing each finding in full.
    findings = [
        _finding("size.function-length", pillar=Pillar.SIZE, symbol="run", line=1),
        _finding("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, symbol="run", line=2),
    ]

    report = ScoreCalculator().calculate(findings, 10)

    offender = report.top_offenders[0]
    assert offender.penalty == 4.0
    assert offender.grade.score == 51.22
