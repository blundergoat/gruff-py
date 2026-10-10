"""Render one analysis journey as Markdown for collaborative review.

The reporter groups findings for pull requests while naming scoring mode and
partial scan context separately so reviewers do not confuse the two.
"""

import json
from collections import defaultdict

from gruffpy.analysis.report import AnalysisReport
from gruffpy.finding.finding import Finding
from gruffpy.scoring.pillar_score import PillarScore


class MarkdownReporter:
    """Present an analysis report as a review-friendly Markdown document.

    Use this reporter for pull-request comments and release notes where users
    need foldable findings plus concise score and scan-context summaries.
    """

    def render(self, report: AnalysisReport) -> str:
        """Render *report* as Markdown with collapsible severity sections (GitHub-compatible).

        Findings are grouped by severity (error / warning / advisory) and
        then by file, wrapped in ``<details open>`` so reviewers can fold
        sections in PR comments.

        Args:
            report: Fully-populated analysis report.

        Returns:
            Markdown document with a trailing newline.
        """
        score = report.score
        counts = report.finding_counts()
        # A diagnostic-only report has no score, so preserve the existing fallback mode.
        scoring_mode = score.scope if score is not None else "full-project"
        lines = [
            "# gruff-py report",
            "",
            (f"**Grade:** {'n/a' if score is None or score.composite is None else score.composite.letter} ({_score_value(score)})"),
            f"**Scoring mode:** {scoring_mode}",
        ]

        # No runner caveat means Markdown must not invent a full scan-context claim.
        if report.partial_context_caveat is not None:
            lines.append(f"**Scan context:** {_md(report.partial_context_caveat)}")
        lines.append(f"**Findings:** {counts['total']} total, {counts['error']} error, {counts['warning']} warning, {counts['advisory']} advisory")

        # Active filters remain visible so users know why some findings are hidden.
        if report.filters is not None and report.filters.is_active():
            lines.append(f"**Filters:** `{json.dumps(report.filters.to_dict(), separators=(',', ':'))}`")

        if report.diagnostics:
            lines.extend(["", "## Diagnostics", ""])
            for diagnostic in report.diagnostics:
                location = diagnostic.file_path or diagnostic.path
                if diagnostic.file_path is not None and diagnostic.line is not None:
                    location = f"{diagnostic.file_path}:{diagnostic.line}"
                suffix = "" if location is None else f" `{_md(location)}`"
                lines.append(f"- **{_md(diagnostic.type)}**{suffix} - {_md(diagnostic.message)}")

        lines.extend(
            [
                "",
                "## Pillars",
                "",
                "| Pillar | Grade | Score | Findings | Advisory | Warning | Error |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for pillar in _pillar_summary_rows(report):
            lines.append(_pillar_row(pillar))

        lines.extend(["", "## Findings", ""])
        if not report.findings:
            lines.append("No findings.")
        else:
            _append_finding_groups(lines, report.findings)

        return "\n".join(lines) + "\n"


def _score_value(score: object | None) -> str:
    if score is None or not hasattr(score, "composite"):
        return "n/a"
    composite = score.composite
    return f"{composite.score:.2f}/100"


def _pillar_summary_rows(report: AnalysisReport) -> list[PillarScore]:
    """Return applicable pillar scores sorted by findings DESC, then pillar ASC.

    Mirrors the canonical Phase 2 summary shape used by the HTML reporter: only
    applicable pillars are included, sourced from the existing ``PillarScore``
    data without recomputing severity counts or scores.

    Args:
        report: Analysis report providing the optional ``ScoreReport``.

    Returns:
        Applicable ``PillarScore`` entries ordered for the canonical table.
    """
    if report.score is None:
        return []
    applicable = [pillar for pillar in report.score.pillars if pillar.applicable]
    applicable.sort(key=lambda pillar: (-pillar.findings, pillar.pillar))
    return applicable


def _pillar_row(pillar: PillarScore) -> str:
    grade = pillar.grade.letter if pillar.grade is not None else "n/a"
    score = f"{pillar.grade.score:.2f}" if pillar.grade is not None else "n/a"
    return f"| {_md(pillar.pillar)} | {_md(grade)} | {_md(score)} | {pillar.findings} | {pillar.advisories} | {pillar.warnings} | {pillar.errors} |"


def _append_finding_groups(lines: list[str], findings: tuple[Finding, ...]) -> None:
    groups: dict[str, dict[str, list[Finding]]] = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        groups[finding.severity.value][finding.file_path].append(finding)

    for severity in ("error", "warning", "advisory"):
        if severity not in groups:
            continue
        count = sum(len(items) for items in groups[severity].values())
        lines.extend([f"<details open><summary>{severity.title()} ({count})</summary>", ""])
        for file_path in sorted(groups[severity]):
            lines.extend([f"**{_md(file_path)}**", ""])
            for finding in groups[severity][file_path]:
                lines.append(_finding_line(finding))
            lines.append("")
        lines.extend(["</details>", ""])


def _finding_line(finding: Finding) -> str:
    location = finding.file_path if finding.line is None else f"{finding.file_path}:{finding.line}"
    symbol = "" if finding.symbol is None else f" `{_md(finding.symbol)}`"
    return f"- **{finding.severity.value}** `{_md(finding.rule_id)}` {_md(location)}{symbol} - {_md(finding.message)}"


def _md(value: str) -> str:
    return value.replace("|", "\\|")
