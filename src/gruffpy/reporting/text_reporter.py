"""Renders an AnalysisReport as plain text for terminal output."""

import shlex

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.finding.finding import Finding
from gruffpy.version import TOOL_NAME


class TextReporter:
    """Render an analysis report as the plain-text terminal output for ``gruff-py analyse``."""

    def render(self, report: AnalysisReport) -> str:
        """Render *report* as the terminal-friendly default ``gruff-py analyse`` output.

        Layout: tool/version header, file counts, ignored/missing path
        listings, run diagnostics, the score block, every finding, and a
        summary footer with severity counts and the exit code.

        Args:
            report: Fully-populated analysis report.

        Returns:
            Trailing-newline-terminated text suitable for stdout.
        """
        counts = report.finding_counts()
        lines: list[str] = [
            f"{TOOL_NAME} {report.tool_version}",
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
        _append_baseline(lines, report)
        _append_score(lines, report)
        _append_findings(lines, report.findings)

        lines.append("")
        lines.append("Summary")
        lines.append(
            f"  Findings: {counts['total']} (advisory: {counts['advisory']}, "
            f"warning: {counts['warning']}, error: {counts['error']})"
        )
        lines.append(f"  Exit code: {report.exit_code}")
        _append_output_volume_hint(lines, report)
        return "\n".join(lines) + "\n"


def _append_output_volume_hint(lines: list[str], report: AnalysisReport) -> None:
    threshold = report.output_volume_hint_threshold
    if threshold <= 0:
        return
    finding_count = len(report.findings)
    if finding_count < threshold:
        return
    paths_display = " ".join(shlex.quote(path) for path in report.requested_paths)
    lines.append("")
    lines.append(f"Hint: {finding_count} findings is a lot to read flat. Try:")
    lines.append(f"  uv run gruff-py summary --group-by=rule {paths_display}".rstrip())


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


def _append_baseline(lines: list[str], report: AnalysisReport) -> None:
    baseline = report.extensions.baseline
    if baseline is None:
        return
    lines.append("")
    lines.append("Baseline")
    lines.append(f"  Path: {baseline.path}")
    lines.append(f"  Source: {baseline.source}")
    lines.append(f"  Entries: {baseline.total_entries}")
    lines.append(f"  Generated: {'yes' if baseline.generated else 'no'}")
    lines.append(f"  Suppressed findings: {baseline.suppressed_findings}")
    lines.append(f"  Stale evaluation: {baseline.stale_evaluation}")
    lines.append(f"  Stale entries: {len(baseline.stale_entries)}")
    if baseline.generated:
        if baseline.source == "default":
            lines.append(f"  Tip: commit {baseline.path} and rerun `gruff-py analyse` to apply it.")
        else:
            lines.append(
                f"  Tip: commit {baseline.path} and rerun with "
                f"`--baseline-path {shlex.quote(baseline.path)}` to apply it."
            )
    elif baseline.stale_entries:
        lines.append(
            "  Tip: regenerate after review with "
            f"`gruff-py analyse . --generate-baseline-path {shlex.quote(baseline.path)}`."
        )


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
