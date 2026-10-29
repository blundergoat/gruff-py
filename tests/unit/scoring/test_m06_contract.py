"""Pin the seven behaviours the ratified family scoring contract fixes.

The cross-port suite (``family-check --suite scoring``) proves the same properties for all five
ports at once, but it runs from the specification repository and needs every port built. These
tests fail here, in gruff-py's own gate, the moment one of them breaks.
"""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.reporting.text_reporter import TextReporter
from gruffpy.scoring.grade import Grade
from gruffpy.scoring.score_calculator import ScoreCalculator
from gruffpy.scoring.score_report import ScoreReport

EVALUATED_FILES = 10
# Duplication factors the scale case applies to findings and files together, so density is unchanged.
DOUBLED = 2
QUADRUPLED = 4
# A reachable pillar that reported nothing scores exactly this.
CLEAN_PILLAR_SCORE = 100.0


def _finding(
    rule_id: str,
    pillar: Pillar,
    severity: Severity,
    *,
    confidence: Confidence = Confidence.HIGH,
    file_path: str = "src/a.py",
    symbol: str | None = None,
    line: int | None = 1,
) -> Finding:
    """Build one finding with an explicit weight so a test can state what it expects.

    Args:
        rule_id: Native rule identifier, the ratified attribution key.
        pillar: Pillar the finding lands in.
        severity: Severity driving the ratified weight.
        confidence: Confidence multiplying that weight.
        file_path: Project-relative path.
        symbol: Qualified symbol, or None for a file-level finding.
        line: Reported line, which the cluster key deliberately ignores.

    Returns:
        One finding ready to score.
    """
    return Finding(
        rule_id=rule_id,
        message=f"{rule_id} fired.",
        file_path=file_path,
        line=line,
        pillar=pillar,
        severity=severity,
        tier=RuleTier.V01,
        confidence=confidence,
        symbol=symbol,
    )


def test_scale_is_not_an_automatic_penalty() -> None:
    """Duplicating a project must not move its grade.

    This is the property the ratified shape exists to deliver: duplication doubles the findings and
    the evaluated files together, so the density they make is unchanged. The retired absolute-sum
    shape failed it - a 4x duplication of identical code cost gruff-py fifteen composite points.
    """
    single = [_finding("naming.one", Pillar.NAMING, Severity.WARNING, file_path="src/a.py")]
    doubled = single + [_finding("naming.one", Pillar.NAMING, Severity.WARNING, file_path="src/b.py")]
    quadrupled = doubled + [
        _finding("naming.one", Pillar.NAMING, Severity.WARNING, file_path="src/c.py"),
        _finding("naming.one", Pillar.NAMING, Severity.WARNING, file_path="src/d.py"),
    ]

    base = ScoreCalculator().calculate(single, EVALUATED_FILES)
    assert base.composite is not None
    assert ScoreCalculator().calculate(doubled, EVALUATED_FILES * DOUBLED).composite == base.composite
    assert ScoreCalculator().calculate(quadrupled, EVALUATED_FILES * QUADRUPLED).composite == base.composite


def _monotonicity_pair() -> tuple[ScoreReport, ScoreReport]:
    """Score the same project before and after one error-severity security finding is added.

    Returns:
        The baseline report and the report carrying the extra finding, at one fixed denominator.
    """
    before = ScoreCalculator().calculate([_finding("security.one", Pillar.SECURITY, Severity.WARNING)], EVALUATED_FILES)
    after = ScoreCalculator().calculate(
        [
            _finding("security.one", Pillar.SECURITY, Severity.WARNING),
            _finding("security.two", Pillar.SECURITY, Severity.ERROR),
        ],
        EVALUATED_FILES,
    )
    return before, after


def _pillar_score(report: ScoreReport, pillar: str) -> float:
    """Read one published pillar score, failing the test rather than returning None.

    Args:
        report: A scored report.
        pillar: Pillar name to read.

    Returns:
        The pillar's score.
    """
    grade = {row.pillar: row.grade for row in report.pillars}[pillar]
    assert grade is not None, f"pillar {pillar} has no score"
    return grade.score


def test_adding_a_finding_worsens_its_own_pillar() -> None:
    """Adding a finding without adding a file can only worsen the pillar it lands in."""
    before, after = _monotonicity_pair()

    assert _pillar_score(after, "security") < _pillar_score(before, "security")


def test_adding_a_finding_leaves_unrelated_pillars_alone() -> None:
    """A pillar that gained no finding must not move, or the composite couples unrelated areas."""
    before, after = _monotonicity_pair()

    assert after.composite is not None and before.composite is not None
    assert after.composite.score < before.composite.score
    assert _pillar_score(after, "documentation") == _pillar_score(before, "documentation")


def test_a_reachable_clean_pillar_scores_one_hundred() -> None:
    """Every pillar an applicable rule can reach reports a perfect score when it finds nothing."""
    clean = ScoreCalculator().calculate([], EVALUATED_FILES)
    scored = {row.pillar: (row.applicable, None if row.grade is None else row.grade.score) for row in clean.pillars}

    assert scored == {row.pillar: (True, CLEAN_PILLAR_SCORE) for row in clean.pillars}


def test_a_run_that_evaluated_nothing_scores_nothing() -> None:
    """Nothing evaluated is null throughout, never a perfect score on an empty directory."""
    nothing = ScoreCalculator().calculate([], 0)

    assert nothing.composite is None
    assert all(pillar.grade is None for pillar in nothing.pillars)
    # The denominator is still published, so a reader can see that nothing was evaluated.
    assert nothing.evaluated_files == 0


def test_serialization_rounds_to_two_decimals_away_from_zero() -> None:
    """Ties round away from zero, matching the four sibling ports.

    Python's built-in ``round`` breaks ties to even, so 53.125 would become 53.12 here while Go, PHP,
    Rust, and JavaScript all produce 53.13 - a cross-port disagreement on the last cent that has
    nothing to do with the formula.
    """
    assert Grade.from_score(53.125).score == 53.13
    assert Grade.from_score(50.005).score == 50.01
    assert Grade.from_score(97.681818).score == 97.68
    assert Grade.from_score(100.0).score == 100.0


def test_clustering_keys_on_symbol_without_line_identity() -> None:
    """Correlated findings on one symbol bill once, whatever lines they report.

    Correlated rules disagree about which line to report - ``size.function-length`` names the
    decorator while the complexity rules name the ``def`` - so a line in the cluster key would split
    one root cause into two and bill it twice.
    """
    report = ScoreCalculator().calculate(
        [
            _finding("size.function-length", Pillar.SIZE, Severity.WARNING, symbol="run", line=1),
            _finding("complexity.cyclomatic", Pillar.COMPLEXITY, Severity.WARNING, symbol="run", line=9),
        ],
        EVALUATED_FILES,
    )

    # One warning weighs 4, so the cluster bills 4 across two members: 2 each.
    weights = {pillar.pillar: pillar.penalty for pillar in report.pillars}
    assert (weights["size"], weights["complexity"]) == (2.0, 2.0)

    # The ratified key carries no line identity, so the published cluster must not name one.
    assert [dict(cluster) for cluster in report.clusters] == [
        {
            "file": "src/a.py",
            "symbol": "run",
            "findings": 2,
            "weight": 4.0,
            "ruleIds": ["complexity.cyclomatic", "size.function-length"],
        },
    ]


def test_two_symbols_in_one_file_do_not_cluster() -> None:
    """Correlated rules on different symbols are different root causes and bill separately."""
    distinct = ScoreCalculator().calculate(
        [
            _finding("size.function-length", Pillar.SIZE, Severity.WARNING, symbol="run", line=1),
            _finding("complexity.cyclomatic", Pillar.COMPLEXITY, Severity.WARNING, symbol="walk", line=9),
        ],
        EVALUATED_FILES,
    )

    assert distinct.clusters == ()


def test_rule_attribution_is_keyed_by_native_rule_id() -> None:
    """Every rule that produced a finding owes exactly one row, sorted by its native identifier."""
    report = ScoreCalculator().calculate(
        [
            _finding("naming.b-rule", Pillar.NAMING, Severity.ADVISORY),
            _finding("naming.a-rule", Pillar.NAMING, Severity.WARNING, confidence=Confidence.MEDIUM),
            _finding("naming.a-rule", Pillar.NAMING, Severity.WARNING, confidence=Confidence.MEDIUM, file_path="src/b.py"),
        ],
        EVALUATED_FILES,
    )

    assert [row["ruleId"] for row in report.rule_attribution] == ["naming.a-rule", "naming.b-rule"]
    # Two warnings at medium confidence weigh 4 * 0.75 each.
    assert report.rule_attribution[0]["findings"] == 2
    assert report.rule_attribution[0]["weight"] == 6.0
    assert report.rule_attribution[1]["findings"] == 1
    assert report.rule_attribution[1]["weight"] == 1.0


def test_text_and_machine_views_agree_on_the_composite() -> None:
    """The composite a person reads and the one a script reads come from one calculation.

    A renderer that formats the score itself, rather than printing what the scorer produced, can
    drift from the machine view without any other test noticing.
    """
    report = ScoreCalculator().calculate(
        [_finding("complexity.cyclomatic", Pillar.COMPLEXITY, Severity.WARNING)],
        EVALUATED_FILES,
    )
    assert report.composite is not None

    payload = report.to_dict()
    assert payload["composite"] == {"score": report.composite.score, "grade": report.composite.letter}
    assert payload["evaluatedFiles"] == EVALUATED_FILES
    assert payload["scoredPillars"] == list(report.scored_pillars)


def test_canonical_block_leads_the_text_view() -> None:
    """FAMILY-CONTRACT section 1 puts the masthead and the composite block first, extensions below."""
    from tests.unit.reporting.test_reporters import _report

    lines = TextReporter().render(_report()).splitlines()

    assert lines[0].startswith("gruff-py ")
    assert lines[0].endswith(" analyse")
    assert lines[1].startswith("Composite: ")
    assert lines[2].startswith("Findings: ")
    # A canonical line repeated below would give a reader two answers to one question.
    assert not any(line.strip().startswith("Composite: ") for line in lines[2:])
