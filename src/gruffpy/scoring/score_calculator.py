"""Convert findings into the scores users compare across analysis runs.

The calculator produces pillar, file, and composite grades and records whether
the score came from normal or diff-filtered findings, not discovery coverage.
"""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.scoring.file_score import FileScore
from gruffpy.scoring.grade import Grade
from gruffpy.scoring.pillar_score import PillarScore
from gruffpy.scoring.score_report import ScoreReport

# Every pillar a built-in rule can emit. The composite averages this whole set, so the divisor is
# the same on every run of the same rule set. Listing fewer let a pillar join the average only when
# it had findings and drop out when its last one was fixed, which lowered the composite for fixing
# a finding whenever that pillar scored above the mean of the others.
# `test_static_pillars_covers_every_catalog_pillar` fails if a new rule introduces a pillar missing
# here. Order is presentation only.
STATIC_PILLARS: tuple[str, ...] = (
    "size",
    "complexity",
    "maintainability",
    "dead-code",
    "naming",
    "documentation",
    "design",
    "security",
    "sensitive-data",
    "test-quality",
    "correctness",
    "modernisation",
)

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.ADVISORY: 1.0,
    Severity.WARNING: 4.0,
    Severity.ERROR: 12.0,
}

CONFIDENCE_WEIGHTS: dict[Confidence, float] = {
    Confidence.LOW: 0.5,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.0,
}

# Ratified family scoring parameters. The shape ``bounded-normalized-density-floored`` was ratified
# 2026-09-01 and these values 2026-09-03; all five ports carry the same numbers, so changing either is
# a family decision rather than a gruff-py one. SCORE_FLOOR bounds how far one saturated pillar can
# drag the composite; DENSITY_SCALE is the per-file finding density at which a pillar sits half way
# between the floor and 100. The retired absolute-sum shape's pillar and file multipliers are gone.
SCORE_FLOOR: float = 50.0
DENSITY_SCALE: float = 0.1
CORRELATED_COMPLEXITY_RULES: frozenset[str] = frozenset(
    {
        "complexity.cognitive",
        "complexity.cyclomatic",
        "complexity.nesting-depth",
        "size.function-length",
        "size.parameter-count",
    }
)


class ScoreCalculator:
    """Calculate grades and top offenders from the findings a user requested.

    Use this service after filtering/suppression so every reporter receives one
    consistent score plus its full-project or diff scoring mode.
    """

    def calculate(
        self,
        findings: list[Finding],
        evaluated_files: int,
        diff_active: bool = False,
    ) -> ScoreReport:
        """Compute the full ``ScoreReport`` from *findings*.

        Each pillar scores on the density of its weighted findings per
        evaluated file, on the ratified curve from ``SCORE_FLOOR`` to 100, so a
        larger project is not penalised for its size. The composite grade is the
        arithmetic mean of applicable pillar scores; top offenders are the 10
        files with the worst grade (ties broken by finding count then path).

        A run that evaluated nothing has no health to report: every pillar score,
        the composite, and both grades are ``None`` rather than a perfect 100.

        Args:
            findings: Findings produced by the rule pass.
            evaluated_files: Ratified scoring denominator - Python files that
                survived discovery and parsed. Zero means nothing was evaluated.
            diff_active: When true, serialized score mode is ``"diff"`` instead
                of ``"full-project"``; it does not describe discovery coverage.

        Returns:
            Score report ready for serialisation and rendering.
        """
        finding_penalties = _finding_penalties(findings)
        pillars = self._pillar_scores(findings, finding_penalties, evaluated_files)
        applicable_scores = [p.grade.score for p in pillars if p.applicable and p.grade is not None]
        average = sum(applicable_scores) / len(applicable_scores) if applicable_scores else None
        scoring_mode = "diff" if diff_active else "full-project"
        return ScoreReport(
            composite=None if average is None else Grade.from_score(average),
            clusters=_correlated_clusters(findings, finding_penalties),
            rule_attribution=_rule_attribution(findings, finding_penalties),
            evaluated_files=evaluated_files,
            scored_pillars=tuple(pillar.pillar for pillar in pillars),
            pillars=tuple(pillars),
            top_offenders=tuple(self._file_scores(findings, finding_penalties, evaluated_files)),
            complexity_distribution=self._complexity_distribution(findings),
            scope=scoring_mode,
            explanation=(
                "Each pillar scores on the density of its weighted findings per "
                "evaluated file, on a curve from 50 to 100, so a larger project "
                "is not penalised for its size; correlated size/complexity "
                "findings on the same symbol share penalty weight; the composite "
                "is the average of applicable pillar scores."
            ),
        )

    def _pillar_scores(
        self,
        findings: list[Finding],
        finding_penalties: dict[int, float],
        evaluated_files: int,
    ) -> list[PillarScore]:
        pillar_names = list(STATIC_PILLARS)
        for finding in findings:
            if finding.pillar.value not in pillar_names:
                pillar_names.append(finding.pillar.value)

        scores: list[PillarScore] = []
        for pillar_name in pillar_names:
            pillar_findings = [f for f in findings if f.pillar.value == pillar_name]
            weight = self._finding_penalty(pillar_findings, finding_penalties)
            counts = self._severity_counts(pillar_findings)
            scores.append(
                PillarScore(
                    pillar=pillar_name,
                    applicable=True,
                    grade=_curve_grade(weight, evaluated_files),
                    findings=len(pillar_findings),
                    advisories=counts[Severity.ADVISORY],
                    warnings=counts[Severity.WARNING],
                    errors=counts[Severity.ERROR],
                    penalty=weight,
                )
            )
        return scores

    def _file_scores(
        self,
        findings: list[Finding],
        finding_penalties: dict[int, float],
        evaluated_files: int,
    ) -> list[FileScore]:
        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file_path, []).append(finding)

        scores: list[FileScore] = []
        for file_path, file_findings in by_file.items():
            counts = self._severity_counts(file_findings)
            # A file's density is its own weighted findings, so file and project scores share one
            # curve and a top-offender list cannot rank code by a rule the project grade never used.
            weight = self._finding_penalty(file_findings, finding_penalties)
            max_cyclomatic = self._max_metadata_int(file_findings, "complexity.cyclomatic", "complexity")
            max_cognitive = self._max_metadata_int(file_findings, "complexity.cognitive", "complexity")
            scores.append(
                FileScore(
                    file_path=file_path,
                    grade=None if evaluated_files <= 0 else _curve_grade(weight, 1),
                    findings=len(file_findings),
                    advisories=counts[Severity.ADVISORY],
                    warnings=counts[Severity.WARNING],
                    errors=counts[Severity.ERROR],
                    penalty=weight,
                    max_cyclomatic=max_cyclomatic,
                    max_cognitive=max_cognitive,
                    max_lines=self._max_line_metric(file_findings),
                )
            )

        # An ungraded file sorts as if perfect, so a run that evaluated nothing ranks by findings alone.
        scores.sort(key=lambda s: (100.0 if s.grade is None else s.grade.score, -s.findings, s.file_path))
        return scores[:10]

    @staticmethod
    def _complexity_distribution(findings: list[Finding]) -> dict[str, int]:
        buckets = {"1-5": 0, "6-10": 0, "11-15": 0, "16-20": 0, "21+": 0}
        for finding in findings:
            if finding.rule_id != "complexity.cyclomatic":
                continue
            value = finding.metadata.get("complexity")
            if not isinstance(value, int):
                continue
            if value <= 5:
                buckets["1-5"] += 1
            elif value <= 10:
                buckets["6-10"] += 1
            elif value <= 15:
                buckets["11-15"] += 1
            elif value <= 20:
                buckets["16-20"] += 1
            else:
                buckets["21+"] += 1
        return buckets

    @staticmethod
    def _finding_penalty(
        findings: list[Finding],
        finding_penalties: dict[int, float],
    ) -> float:
        return sum(finding_penalties.get(id(finding), _base_penalty(finding)) for finding in findings)

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
        counts = {Severity.ADVISORY: 0, Severity.WARNING: 0, Severity.ERROR: 0}
        for finding in findings:
            counts[finding.severity] += 1
        return counts

    @staticmethod
    def _max_metadata_int(findings: list[Finding], rule_id: str, key: str) -> int | None:
        result: int | None = None
        for finding in findings:
            if finding.rule_id != rule_id:
                continue
            value = finding.metadata.get(key)
            if not isinstance(value, int):
                continue
            result = value if result is None else max(result, value)
        return result

    @staticmethod
    def _max_line_metric(findings: list[Finding]) -> int | None:
        target_rules = {"size.file-length", "size.function-length", "size.class-length"}
        result: int | None = None
        for finding in findings:
            if finding.rule_id not in target_rules:
                continue
            value = finding.metadata.get("lines")
            if not isinstance(value, int):
                continue
            result = value if result is None else max(result, value)
        return result


def _correlated_clusters(findings: list[Finding], penalties: dict[int, float]) -> tuple[dict[str, object], ...]:
    """List every correlated concept that billed one shared weight.

    A reader can then see which findings the grade counted once, rather than inferring it from a
    total that is lower than the sum of its parts. Sorted by file then symbol, so two runs over
    unchanged input publish the same bytes.

    Args:
        findings: Scored findings for the run.
        penalties: Clustered weight per finding, keyed by ``id()``.

    Returns:
        One row per cluster of two or more findings; empty when nothing clustered.
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        if finding.rule_id not in CORRELATED_COMPLEXITY_RULES or finding.symbol is None:
            continue
        groups.setdefault((finding.file_path, finding.symbol), []).append(finding)

    clusters: list[dict[str, object]] = []
    for (file_path, symbol), group in groups.items():
        # A lone correlated finding billed its own full weight, so it is not a cluster to report.
        if len(group) < 2:
            continue
        weight = sum(penalties.get(id(finding), 0.0) for finding in group)
        clusters.append(
            {
                "file": file_path,
                "symbol": symbol,
                "ruleIds": sorted(finding.rule_id for finding in group),
                "findings": len(group),
                "weight": _round_weight(weight),
            }
        )

    clusters.sort(key=lambda cluster: (str(cluster["file"]), str(cluster["symbol"])))
    return tuple(clusters)


def _rule_attribution(findings: list[Finding], penalties: dict[int, float]) -> tuple[dict[str, object], ...]:
    """Report how much weight each native rule removed from the score.

    The key is the native ``rule_id``: a concept identifier may group reporting, but the ratified
    contract never makes it the attribution key. Sorted by rule identifier for deterministic output.

    Args:
        findings: Scored findings for the run.
        penalties: Clustered weight per finding, keyed by ``id()``.

    Returns:
        One row per native rule that carried weight; empty when the run produced no findings.
    """
    counts: dict[str, int] = {}
    weights: dict[str, float] = {}
    for finding in findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        weights[finding.rule_id] = weights.get(finding.rule_id, 0.0) + penalties.get(id(finding), 0.0)

    return tuple({"ruleId": rule_id, "findings": counts[rule_id], "weight": _round_weight(weights[rule_id])} for rule_id in sorted(counts))


def _round_weight(weight: float) -> float:
    """Round one weight to the ratified two decimals, never emitting negative zero.

    Args:
        weight: Summed severity-by-confidence weight.

    Returns:
        The weight at two decimal places.
    """
    rounded = round(weight, 2)
    return 0.0 if rounded == 0 else rounded


def _curve_grade(weight: float, evaluated_files: int) -> Grade | None:
    """Apply the ratified pillar curve to one summed weight.

    The curve is ``floor + (100 - floor) / (1 + density / densityScale)``, where density is the
    weight divided by the evaluated-file count. Dividing before transforming is what makes a
    duplicated project score the same as the original: twice the findings over twice the code is the
    same ratio, where the retired absolute-sum shape scored the duplicate far worse.

    Args:
        weight: Summed severity-by-confidence weight; zero means reachable and clean.
        evaluated_files: Ratified denominator; zero or less means nothing was evaluated.

    Returns:
        The graded score between the ratified floor and 100, or ``None`` when nothing was evaluated
        and inventing a grade would present an unscanned project as perfect.
    """
    if evaluated_files <= 0:
        return None

    density = weight / evaluated_files
    return Grade.from_score(SCORE_FLOOR + (100.0 - SCORE_FLOOR) / (1.0 + density / DENSITY_SCALE))


def _finding_penalties(findings: list[Finding]) -> dict[int, float]:
    penalties = {id(finding): _base_penalty(finding) for finding in findings}
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        if finding.rule_id not in CORRELATED_COMPLEXITY_RULES or finding.symbol is None or finding.line is None:
            continue
        # Key on the qualified symbol only, not the line: size.function-length reports
        # the decorator line while complexity rules report the def line, so a line in
        # the key splits a decorated function's findings and skips down-weighting.
        key = (finding.file_path, finding.symbol)
        groups.setdefault(key, []).append(finding)
    for group in groups.values():
        if len(group) < 2:
            continue
        penalty = max(_base_penalty(finding) for finding in group) / len(group)
        for finding in group:
            penalties[id(finding)] = penalty
    return penalties


def _base_penalty(finding: Finding) -> float:
    return SEVERITY_WEIGHTS[finding.severity] * CONFIDENCE_WEIGHTS[finding.confidence]
