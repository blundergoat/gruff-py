from gruff.analysis.report import AnalysisReport
from gruff.analysis.run_diagnostic import RunDiagnostic
from gruff.finding.finding import Finding


class TextReporter:
    def render(self, report: AnalysisReport) -> str:
        counts = report.finding_counts()
        lines: list[str] = [
            f"gruff {report.tool_version}",
            f"Format: {report.format}",
            f"Fail threshold: {report.fail_on}",
            "",
            "Files",
            f"  Discovered: {report.files_discovered}",
            f"  Parsed: {report.files_parsed}",
            f"  Ignored: {len(report.ignored_paths)}",
            f"  Missing: {len(report.missing_paths)}",
            f"  Parse errors: {report.parse_error_count()}",
        ]
        _append_path_section(lines, "Ignored paths", report.ignored_paths)
        _append_path_section(lines, "Missing paths", report.missing_paths)
        _append_diagnostics(lines, report.diagnostics)
        _append_score(lines, report)
        _append_findings(lines, report.findings)

        lines.append("")
        lines.append("Summary")
        lines.append(
            f"  Findings: {counts['total']} (advisory: {counts['advisory']}, "
            f"warning: {counts['warning']}, error: {counts['error']})"
        )
        lines.append(f"  Exit code: {report.exit_code}")
        return "\n".join(lines) + "\n"


def _append_path_section(lines: list[str], title: str, paths: tuple[str, ...]) -> None:
    if not paths:
        return
    lines.append("")
    lines.append(title)
    for path in paths:
        lines.append(f"  {path}")


def _append_diagnostics(lines: list[str], diagnostics: tuple[RunDiagnostic, ...]) -> None:
    if not diagnostics:
        return
    lines.append("")
    lines.append("Diagnostics")
    for diagnostic in diagnostics:
        location = diagnostic.file_path
        if location is not None and diagnostic.line is not None:
            location = f"{location}:{diagnostic.line}"
        if location is None:
            location = diagnostic.path
        prefix = diagnostic.type.upper()
        if location is None:
            lines.append(f"  [{prefix}] {diagnostic.message}")
        else:
            lines.append(f"  [{prefix}] {location} {diagnostic.message}")


def _append_score(lines: list[str], report: AnalysisReport) -> None:
    if report.score is None:
        return
    lines.append("")
    lines.append("Score")
    lines.append(
        f"  Composite: {report.score.composite.letter} ({report.score.composite.score:.2f}/100)"
    )
    lines.append(f"  Scope: {report.score.scope}")
    lines.append("  Pillars:")
    for pillar in report.score.pillars:
        if pillar.grade is None:
            grade_letter = "n/a"
            grade_score = "n/a"
        else:
            grade_letter = pillar.grade.letter
            grade_score = f"{pillar.grade.score:.2f}"
        lines.append(
            f"    {pillar.pillar}: {grade_letter} ({grade_score}) findings={pillar.findings}"
        )


def _append_findings(lines: list[str], findings: tuple[Finding, ...]) -> None:
    lines.append("")
    lines.append("Findings")
    if not findings:
        lines.append("  None")
        return
    for finding in findings:
        location = finding.file_path
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        lines.append(f"  [{finding.severity.value}] {finding.rule_id}")
        lines.append(f"    {location}")
        lines.append(f"    {finding.message}")
