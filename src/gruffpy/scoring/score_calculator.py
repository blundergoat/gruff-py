"""Converts findings into the per-pillar / per-file / composite scores in a ``ScoreReport``."""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.scoring.file_score import FileScore
from gruffpy.scoring.grade import Grade
from gruffpy.scoring.pillar_score import PillarScore
from gruffpy.scoring.score_report import ScoreReport

STATIC_PILLARS: tuple[str, ...] = (
    "size",
    "complexity",
    "maintainability",
    "dead-code",
    "naming",
    "documentation",
    "modernisation",
    "security",
    "sensitive-data",
    "test-quality",
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

PILLAR_PENALTY_MULTIPLIER: float = 4.0
FILE_PENALTY_MULTIPLIER: float = 5.0


class ScoreCalculator:
    def calculate(
        self,
        findings: list[Finding],
        diff_active: bool = False,
    ) -> ScoreReport:
        pillars = self._pillar_scores(findings)
        applicable_scores = [p.grade.score for p in pillars if p.applicable and p.grade is not None]
        average = sum(applicable_scores) / len(applicable_scores) if applicable_scores else 100.0
        scope = "diff" if diff_active else "full-project"
        return ScoreReport(
            composite=Grade.from_score(average),
            pillars=tuple(pillars),
            top_offenders=tuple(self._file_scores(findings)),
            complexity_distribution=self._complexity_distribution(findings),
            scope=scope,
            explanation=(
                "Per-pillar scores start at 100 and subtract weighted finding "
                "penalties; the composite is the average of applicable pillar scores."
            ),
        )

    def _pillar_scores(self, findings: list[Finding]) -> list[PillarScore]:
        pillar_names = list(STATIC_PILLARS)
        for finding in findings:
            if finding.pillar.value not in pillar_names:
                pillar_names.append(finding.pillar.value)

        scores: list[PillarScore] = []
        for pillar_name in pillar_names:
            pillar_findings = [f for f in findings if f.pillar.value == pillar_name]
            penalty = self._finding_penalty(pillar_findings) * PILLAR_PENALTY_MULTIPLIER
            counts = self._severity_counts(pillar_findings)
            scores.append(
                PillarScore(
                    pillar=pillar_name,
                    applicable=True,
                    grade=Grade.from_score(100.0 - penalty),
                    findings=len(pillar_findings),
                    advisories=counts[Severity.ADVISORY],
                    warnings=counts[Severity.WARNING],
                    errors=counts[Severity.ERROR],
                    penalty=penalty,
                )
            )
        return scores

    def _file_scores(self, findings: list[Finding]) -> list[FileScore]:
        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file_path, []).append(finding)

        scores: list[FileScore] = []
        for file_path, file_findings in by_file.items():
            counts = self._severity_counts(file_findings)
            penalty = self._finding_penalty(file_findings) * FILE_PENALTY_MULTIPLIER
            max_cyclomatic = self._max_metadata_int(
                file_findings, "complexity.cyclomatic", "complexity"
            )
            max_cognitive = self._max_metadata_int(
                file_findings, "complexity.cognitive", "complexity"
            )
            scores.append(
                FileScore(
                    file_path=file_path,
                    grade=Grade.from_score(100.0 - penalty),
                    findings=len(file_findings),
                    advisories=counts[Severity.ADVISORY],
                    warnings=counts[Severity.WARNING],
                    errors=counts[Severity.ERROR],
                    penalty=penalty,
                    max_cyclomatic=max_cyclomatic,
                    max_cognitive=max_cognitive,
                    max_lines=self._max_line_metric(file_findings),
                )
            )

        scores.sort(key=lambda s: (s.grade.score, -s.findings, s.file_path))
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
    def _finding_penalty(findings: list[Finding]) -> float:
        return sum(
            SEVERITY_WEIGHTS[f.severity] * CONFIDENCE_WEIGHTS[f.confidence] for f in findings
        )

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
        target_rules = {"size.file-length", "size.method-length", "size.class-length"}
        result: int | None = None
        for finding in findings:
            if finding.rule_id not in target_rules:
                continue
            value = finding.metadata.get("lines")
            if not isinstance(value, int):
                continue
            result = value if result is None else max(result, value)
        return result
