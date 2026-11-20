from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.rule.catalog import catalog_definitions
from gruffpy.scoring.score_calculator import STATIC_PILLARS, ScoreCalculator

CORRELATED_STACK_FINDINGS = 4


def _correlated_stack() -> list[Finding]:
    """Build synthetic length and complexity findings on one symbol to exercise shared cluster penalties.

    Returns:
        Four warning findings on symbol run at line 1: function length, cyclomatic, cognitive and nesting depth.
    """
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
    """Build a finding in x.py whose message names its rule, defaulting to symbol run at line 1.

    Args:
        rule_id: Rule id, also named in the message.
        pillar: Pillar the finding scores against.
        lines: Measured line count stored in metadata, or None to leave metadata empty.
        symbol: Symbol used for correlated clustering; None disables clustering; run by default.
        line: Start line stored on the finding. Defaults to 1. Pass None to omit the location and still allow clustering by symbol.
        severity: Severity supplying the weight before confidence scaling. Defaults to warning.
        confidence: Confidence level that selects the multiplier for the severity weight before clustering. Defaults to high.

    Returns:
        A V01 finding with the requested scoring fields and optional line-count metadata.
    """
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

    An unnamed pillar enters the average only when it has findings, changing the divisor between runs.
    Removing its last finding can therefore lower the composite.

    Returns:
        None. Checks that STATIC_PILLARS contains all primary and secondary catalog pillars.
    """
    catalog_pillars = {definition.pillar.value for definition in catalog_definitions()}
    catalog_pillars.update(secondary.value for definition in catalog_definitions() for secondary in definition.secondary_pillars)

    assert catalog_pillars - set(STATIC_PILLARS) == set()


def test_score_report_grades_every_static_pillar_with_no_findings():
    """List every static pillar in order, design, modernisation and correctness included, in a report with no findings.

    Returns:
        None. Checks the pillar order and the presence of design, modernisation, and correctness.
    """
    report = ScoreCalculator().calculate([], 10)
    pillars = [score.pillar for score in report.pillars]

    assert pillars == list(STATIC_PILLARS)
    assert {"design", "modernisation", "correctness"} <= set(pillars)


def test_fixing_the_last_finding_in_a_pillar_cannot_lower_the_composite():
    """Check that clearing the modernisation findings preserves the pillar count and keeps the composite score at least as high.

    Returns:
        None. Compares the pillar count and composite score before and after clearing those findings.
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
    """Never lower the composite score by removing the last correctness findings from an otherwise noisy report.

    Returns:
        None. Compares the pillar counts and composite scores before and after the removal.
    """
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
    """Take a file's max lines from its function-length finding, not from another size rule's line metadata.

    Returns:
        None. Checks that the top offender uses the function-length value despite the larger parameter-count value.
    """
    expected_max_lines = 75
    findings = [
        _finding("size.function-length", pillar=Pillar.SIZE, lines=expected_max_lines),
        _finding("size.parameter-count", pillar=Pillar.SIZE, lines=999),
    ]

    report = ScoreCalculator().calculate(findings, 10)

    assert report.top_offenders[0].max_lines == expected_max_lines


def test_correlated_size_complexity_stack_is_downweighted_for_file_score():
    """Bill a four-rule size and complexity stack on one symbol as one 4.0 penalty, for a 51.22 file score.

    Returns:
        None. Checks the top offender's finding count, shared penalty, and numeric score.
    """
    report = ScoreCalculator().calculate(_correlated_stack(), 10)

    offender = report.top_offenders[0]
    assert offender.findings == CORRELATED_STACK_FINDINGS
    assert offender.penalty == 4.0
    assert offender.grade.score == 51.22


def test_correlated_size_complexity_stack_is_downweighted_for_composite_score():
    """Score the correlated stack's composite at 94.79, with size and complexity penalties of 1.0 and 3.0 and none for design.

    Returns:
        None. Checks the composite score and the size, complexity, and design penalties.
    """
    report = ScoreCalculator().calculate(_correlated_stack(), 10)

    # Size 1.0 and complexity 3.0 give pillar scores 75.00 and 62.50 over ten files.
    # The remaining pillars score 100.00, giving the asserted composite of 1137.50 / 12.
    assert report.composite.score == 94.79
    pillar_penalties = {pillar.pillar: pillar.penalty for pillar in report.pillars}
    assert pillar_penalties["size"] == 1.0
    assert pillar_penalties["complexity"] == 3.0
    assert pillar_penalties["design"] == 0.0


def test_correlated_downweighting_requires_same_symbol():
    """Bill size and complexity findings on different symbols separately, for an 8.0 penalty and a 50.62 file score.

    Returns:
        None. Checks the file penalty and numeric score for findings on separate symbols.
    """
    findings = [
        _finding("size.function-length", pillar=Pillar.SIZE, symbol="left", line=1),
        _finding("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, symbol="right", line=1),
    ]

    report = ScoreCalculator().calculate(findings, 10)

    offender = report.top_offenders[0]
    assert offender.penalty == 8.0
    assert offender.grade.score == 50.62


def test_correlated_findings_without_a_line_share_one_penalty():
    """Charge one shared penalty for correlated findings that carry no line, matching the cluster the report publishes.

    The two warnings split one 4.0 penalty into 2.0 each, so the complexity pillar and the cluster row both report 4.0.

    Returns:
        None. Checks both the complexity penalty and the published cluster weight.
    """
    findings = [
        _finding("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, symbol="run", line=None),
        _finding("complexity.cognitive", pillar=Pillar.COMPLEXITY, symbol="run", line=None),
    ]

    report = ScoreCalculator().calculate(findings, 10)

    pillar_penalties = {pillar.pillar: pillar.penalty for pillar in report.pillars}
    assert pillar_penalties["complexity"] == 4.0
    assert [cluster["weight"] for cluster in report.clusters] == [4.0]


def test_correlated_downweighting_groups_decorated_function_across_lines():
    """Cluster one symbol's findings on its decorator and def lines into one 4.0 penalty, for a 51.22 file score.

    Returns:
        None. Checks the resulting file penalty and numeric score.
    """
    # size.function-length reports the first decorator and complexity rules report the def line.
    # Both rules report the decorated function under the same symbol.
    # Including the line in the cluster key would charge each finding in full.
    findings = [
        _finding("size.function-length", pillar=Pillar.SIZE, symbol="run", line=1),
        _finding("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, symbol="run", line=2),
    ]

    report = ScoreCalculator().calculate(findings, 10)

    offender = report.top_offenders[0]
    assert offender.penalty == 4.0
    assert offender.grade.score == 51.22
