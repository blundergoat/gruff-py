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
        """Grade pillars by penalty density across evaluated files and grade each offending file by its own weighted penalty.

        The composite averages applicable pillars; at most ten offending files are ranked by grade, finding count and path.
        With no evaluated files, all grades are None.

        Args:
            findings: Run findings to score. With none and at least one evaluated file, applicable pillars and the composite earn a perfect grade.
            evaluated_files: Number of discovered Python files that parsed; zero or less leaves all grades None.
            diff_active: Selects diff instead of full-project as the serialized score mode; it does not describe discovery coverage.

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
        """Score every static pillar on every run, plus any other pillar a finding names, which joins the composite only when it has findings.

        A static pillar with no findings is still scored, at zero weight, so it earns a perfect grade when files were evaluated instead of dropping
        out of the composite average. Pillars outside STATIC_PILLARS are appended in the order their first finding appears.

        Args:
            findings: Scored findings for the run; each is assigned to the pillar its pillar value names.
            finding_penalties: Clustered weight per finding, keyed by id(); a finding missing from the map falls back to its base
                severity-by-confidence weight.
            evaluated_files: Density denominator for every pillar; zero or less leaves every pillar grade None.

        Returns:
            One applicable PillarScore per pillar, in STATIC_PILLARS order followed by any extra pillars, carrying its finding and severity counts,
            summed penalty and curve grade; the grade is None when nothing was evaluated.
        """
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
        """Grade each file that carries findings on its own weight and return the ten worst as the top offenders.

        Each file is graded by applying the pillar curve to its total finding weight with a denominator of one.
        Results sort by lowest score, then by higher finding count, then by path. Files with no findings never appear.

        Args:
            findings: Scored findings for the run, grouped here by file path.
            finding_penalties: Clustered weight per finding, keyed by id(); a finding missing from the map falls back to its base
                severity-by-confidence weight.
            evaluated_files: Run-level evaluated-file count, used only as a gate: zero or less leaves every file grade None, and the list then ranks
                by finding count and path alone.

        Returns:
            At most ten FileScore entries, worst first, each with severity counts and summed penalty. Cyclomatic and cognitive maxima use their
            respective rules. The line maximum uses file, function and class length rules. Each maximum is None without qualifying integer metadata.
        """
        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file_path, []).append(finding)

        scores: list[FileScore] = []
        for file_path, file_findings in by_file.items():
            counts = self._severity_counts(file_findings)
            # Reuse the run's cluster adjustments so a finding contributes the same penalty to its file and pillar totals.
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

        # When no file has a grade, higher finding counts rank first and path breaks ties.
        scores.sort(key=lambda s: (100.0 if s.grade is None else s.grade.score, -s.findings, s.file_path))
        return scores[:10]

    @staticmethod
    def _complexity_distribution(findings: list[Finding]) -> dict[str, int]:
        """Sort the complexity value of each cyclomatic-complexity finding into the five fixed bands the score report publishes.

        Args:
            findings: Scored findings for the run; only complexity.cyclomatic findings with an integer complexity metadata value are counted, and all
                others are skipped.

        Returns:
            Counts keyed by the bands 1-5, 6-10, 11-15, 16-20 and 21+; every band is present and stays zero when no finding falls in it.
        """
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
        """Total the penalty weight used to grade a group of findings, such as one pillar or file.

        Args:
            findings: The findings to total.
            finding_penalties: Clustered weight per finding, keyed by id(); a finding absent from the map contributes its base severity-by-confidence
                weight.

        Returns:
            The summed weight; zero for an empty list.
        """
        return sum(finding_penalties.get(id(finding), _base_penalty(finding)) for finding in findings)

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
        """Count findings by severity so pillar and file scores can report advisories, warnings and errors separately.

        Args:
            findings: The findings to count.

        Returns:
            A count for each of ADVISORY, WARNING and ERROR; all three keys are always present and stay zero when no finding has that severity.
        """
        counts = {Severity.ADVISORY: 0, Severity.WARNING: 0, Severity.ERROR: 0}
        for finding in findings:
            counts[finding.severity] += 1
        return counts

    @staticmethod
    def _max_metadata_int(findings: list[Finding], rule_id: str, key: str) -> int | None:
        """Find the largest integer metadata value one rule reported within a set of findings, such as a file's worst cyclomatic complexity.

        Args:
            findings: The findings to scan, typically one file's.
            rule_id: Only findings from this rule are considered.
            key: Metadata key whose integer value is compared; a missing or non-integer value is skipped.

        Returns:
            The largest integer found, or None when no finding from the rule carries an integer value under the key.
        """
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
        """Report the longest line count any file, function or class length finding recorded, for a top offender's max lines figure.

        Args:
            findings: The findings to scan, typically one file's; only size.file-length, size.function-length and size.class-length findings with an
                integer lines metadata value count.

        Returns:
            The largest lines value, or None when no length finding carries an integer lines value.
        """
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
    """Report shared complexity and size penalties by file and symbol.

    Rows report the rule IDs, finding count and rounded shared penalty, ordered by file and symbol.

    Args:
        findings: Run findings. Only findings from correlated complexity rules with a symbol can form a cluster for the same file and symbol.
        penalties: Clustered weight per finding, keyed by id(); a missing entry contributes zero to the reported cluster weight.

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
        # A lone eligible finding keeps its full penalty, so there is no shared penalty to report.
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
    """Report the total scoring penalty weight attributed to each native rule.

    The key is the native rule_id: a concept identifier may group reporting, but does not identify attribution rows.
    Rows are sorted by rule identifier for deterministic output.

    Args:
        findings: Scored findings for the run.
        penalties: Clustered weight keyed by each finding's id(); a missing entry contributes zero weight.

    Returns:
        One row per native rule with its finding count and rounded penalty weight, including zero-weight rules. Empty when there are no findings.
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

    The curve is floor + (100 - floor) / (1 + density / densityScale), where density is the weight per evaluated file.
    Duplicating both the code and its findings leaves that ratio unchanged.

    Args:
        weight: Sum of severity-by-confidence weights. Zero gives a score of 100 when files were evaluated.
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
    """Assign every finding its scoring weight, sharing one weight across correlated size and complexity findings on a symbol.

    Findings from CORRELATED_COMPLEXITY_RULES sharing a file and symbol split the group's highest base weight equally.
    Other findings retain their base weight; a None symbol prevents grouping.

    Args:
        findings: Scored findings for the run.

    Returns:
        Weight per finding keyed by id() of each finding object, so lookups must use the same objects passed here.
    """
    penalties = {id(finding): _base_penalty(finding) for finding in findings}
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        if finding.rule_id not in CORRELATED_COMPLEXITY_RULES or finding.symbol is None:
            continue
        # Group by file and qualified symbol because decorated functions can have different reported lines across rules.
        # Findings without a line can still share the symbol's penalty.
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
    """Weigh one finding by its severity multiplied by its confidence, before any correlated-cluster sharing.

    Args:
        finding: The finding to weigh.

    Returns:
        The SEVERITY_WEIGHTS value for its severity times the CONFIDENCE_WEIGHTS value for its confidence, from 0.5 for a low-confidence advisory to
        12.0 for a high-confidence error.
    """
    return SEVERITY_WEIGHTS[finding.severity] * CONFIDENCE_WEIGHTS[finding.confidence]
