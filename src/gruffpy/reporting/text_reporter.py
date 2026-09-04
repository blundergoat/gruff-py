"""Render one analysis journey as plain text for terminal review.

The reporter keeps the family score/finding block stable while adding Python
run details that help users distinguish scan context from scoring mode.
"""

import shlex

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.finding.finding import Finding
from gruffpy.version import TOOL_NAME


class TextReporter:
    """Present an analysis report in the default terminal-friendly layout.

    Use this reporter when a user runs ``gruff-py analyse`` without selecting
    a machine-readable or browser format.
    """

    def render(self, report: AnalysisReport) -> str:
        """Render *report* as the terminal-friendly default ``gruff-py analyse`` output.

        Layout: tool/version header, file counts, ignored/missing path
        listings, run diagnostics, the score block, every finding, the
        sensitive-exclusion total, and a summary footer with severity
        counts and the exit code.

        Args:
            report: Fully-populated analysis report.

        Returns:
            Trailing-newline-terminated text suitable for stdout.
        """
        counts = report.finding_counts()
        # FAMILY-CONTRACT section 1: masthead, then the two-line composite block, then every gruff-py
        # extension. The run metadata used to sit between them, which put the number a reader came
        # for further down than the contract allows and out of line with the sibling ports.
        lines: list[str] = [f"{TOOL_NAME} {report.tool_version} analyse"]
        _append_canonical_block(lines, report, counts)
        lines += [
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
        _append_ignored_section(lines, report)
        _append_path_section(lines, "Missing paths", report.missing_paths)
        _append_config_warnings(lines, report)
        _append_diagnostics(lines, report.diagnostics)
        _append_baseline(lines, report)
        _append_score(lines, report)
        _append_findings(lines, report.findings)
        _append_scoring_mode(lines, report)
        append_sensitive_exclusions(lines, report)
        _append_partial_context_caveat(lines, report)

        lines.append("")
        lines.append("Summary")
        lines.append(f"  Exit code: {report.exit_code}")
        _append_output_volume_hint(lines, report)
        return "\n".join(lines) + "\n"


def _append_canonical_block(lines: list[str], report: AnalysisReport, counts: dict[str, int]) -> None:
    """Append the two canonical score lines the family contract puts under every masthead.

    FAMILY-CONTRACT section 1 fixes both lines byte-for-byte: the composite carries two decimals and
    the tally is error-first with middot separators. A run that evaluated nothing has no composite,
    and printing 100.00 there would call an empty scan perfect.

    Args:
        lines: Output accumulator receiving the two lines in place.
        report: Fully-populated analysis report.
        counts: Severity tally for the run.

    Returns:
        None; the supplied output list receives the canonical block in place.
    """
    composite = None if report.score is None else report.score.composite
    if composite is None:
        lines.append("Composite: n/a (nothing evaluated)")
    else:
        lines.append(f"Composite: {composite.letter} ({composite.score:.2f} / 100)")
    lines.append(f"Findings: {counts['total']} total · {counts['error']} error · {counts['warning']} warning · {counts['advisory']} advisory")


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


def _append_ignored_section(lines: list[str], report: AnalysisReport) -> None:
    if not report.ignored_paths:
        return
    details = {detail.path: detail for detail in report.ignored_path_details}
    lines.append("")
    lines.append("Ignored paths")
    for path in report.ignored_paths:
        detail = details.get(path)
        if detail is None:
            lines.append(f"  {path}")
        elif detail.pattern is not None:
            lines.append(f"  {path}  ({detail.source}: {detail.pattern})")
        else:
            lines.append(f"  {path}  ({detail.source})")


def _append_config_warnings(lines: list[str], report: AnalysisReport) -> None:
    if not report.config_warnings:
        return
    lines.append("")
    lines.append("Config warnings")
    for warning in report.config_warnings:
        lines.append(f"  {warning}")


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
            lines.append(f"  Tip: commit {baseline.path} and rerun with `--baseline-path {shlex.quote(baseline.path)}` to apply it.")
    elif baseline.stale_entries:
        lines.append(f"  Tip: regenerate after review with `gruff-py analyse . --generate-baseline-path {shlex.quote(baseline.path)}`.")


def append_sensitive_exclusions(lines: list[str], report: AnalysisReport) -> None:
    """Show how many sensitive-data findings configuration removed, and under which rationale.

    Follows the family total gruff-rs renders (``gruff-rs/src/render/text.rs``, search:
    ``Suppressed findings:``) so no configured suppression is invisible in terminal output.

    Shared with the ``summary`` command: FAMILY-CONTRACT.md (search: ``**Where the audit must
    appear**``) requires every surface that applies an exclusion to publish the count on that same
    surface, so both text surfaces render this one section instead of two wordings.

    Args:
        lines: Terminal output lines collected for the current analyse or summary journey.
        report: Run result carrying one audit row per configured exclusion.

    Returns:
        None; the supplied output list gains a section only when a finding was suppressed.
    """
    total = sum(summary.suppressed for summary in report.suppressions)
    # A run where no configured scope matched has no suppression total to reconcile.
    if total == 0:
        return
    details = "; ".join(
        f"sensitiveExclusions[{summary.index}] {summary.rule}: {summary.suppressed} ({summary.reason})"
        for summary in report.suppressions
        if summary.suppressed > 0
    )
    lines.append("")
    lines.append("Sensitive exclusions")
    lines.append(f"  Suppressed findings: {total} via {details}")


def _append_partial_context_caveat(lines: list[str], report: AnalysisReport) -> None:
    """Append the runner's partial-project warning as the user's scan context.

    Args:
        lines: Terminal output lines collected for the current analysis journey.
        report: Run result; a missing caveat means no scan-context claim is shown.

    Returns:
        None; the supplied output list is updated only when a caveat exists.
    """
    # No caveat means the runner cannot claim either partial or full scan context.
    if report.partial_context_caveat is None:
        return
    lines.append("")
    lines.append("Scan context")
    lines.append(f"  Caveat: {report.partial_context_caveat}")


def _append_scoring_mode(lines: list[str], report: AnalysisReport) -> None:
    """Show how the displayed score was calculated after frozen finding output.

    Args:
        lines: Terminal output lines collected for the current analysis journey.
        report: Run result; a missing score means no scoring mode can be shown.

    Returns:
        None; the supplied output list receives a mode only when a score exists.
    """
    # A diagnostic-only run has no score, so users have no scoring mode to review.
    if report.score is None:
        return
    lines.append("")
    lines.append(f"  Scoring mode: {report.score.scope}")


def _append_score(lines: list[str], report: AnalysisReport) -> None:
    """Append the per-pillar score detail for the user's quality review.

    The composite and the tally now lead the view as the canonical block, so this block carries only
    the detail beneath them; it no longer needs the severity counts it once printed.

    Args:
        lines: Terminal output lines collected for the current analysis journey.
        report: Run result; a missing score means no score block is rendered.

    Returns:
        None; the supplied output list receives the score presentation in place.
    """
    # A diagnostic-only report may have no score for the user to review.
    if report.score is None:
        return
    lines.append("")
    lines.append("Score")
    # The composite and tally lead the view under the canonical contract, so the Score block carries
    # only the per-pillar detail; repeating them here would give a reader two answers to one question.
    if report.hidden_by_display_filter > 0:
        lines.append(f"  Display filters hid {report.hidden_by_display_filter} findings; score and exit code reflect all findings.")
    lines.append("  Pillars:")
    # Each pillar row lets the user trace the composite back to one quality area.
    for pillar in report.score.pillars:
        # A non-applicable pillar has no grade, so the terminal shows n/a explicitly.
        if pillar.grade is None:
            grade_letter = "n/a"
            grade_score = "n/a"
        else:
            grade_letter = pillar.grade.letter
            grade_score = f"{pillar.grade.score:.2f}"
        lines.append(f"    {pillar.pillar}: {grade_letter} ({grade_score}) findings={pillar.findings}")


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
        # FAMILY-CONTRACT section 1 made the rs/ts dash-line the family canon at this break:
        # `- [severity] file:line ruleId - message`. gruff-py emitted a three-line block, so the same
        # finding took three lines here and one line in two sibling ports.
        lines.append(f"- [{finding.severity.value}] {location} {finding.rule_id} - {finding.message}")
