"""Render one analysis journey as plain text for terminal review.

The reporter keeps the family score/finding block stable while adding Python
run details that help users distinguish scan context from scoring mode.
"""

import shlex

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.suppression_summary import suppression_audit_text
from gruffpy.finding.finding import Finding
from gruffpy.version import TOOL_NAME


class TextReporter:
    """Present an analysis report in the default terminal-friendly layout.

    Use this reporter when a user runs ``gruff-py analyse`` without selecting
    a machine-readable or browser format.
    """

    def render(self, report: AnalysisReport) -> str:
        """Render terminal analysis output with the tool header, canonical score and finding tally first.

        Run details, optional sections, pillar scores and findings follow; the footer reports the exit code.

        Args:
            report: Analysis results supplying the displayed counts, scores, diagnostics, paths and findings.

        Returns:
            Trailing-newline-terminated text suitable for stdout.
        """
        counts = report.finding_counts()
        # FAMILY-CONTRACT section 1 keeps the composite and finding tally immediately below the masthead.
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

    FAMILY-CONTRACT section 1 requires two-decimal scores and an error-first tally with middot separators.
    A missing composite prints n/a so an empty scan is not presented as perfect.

    Args:
        lines: Output accumulator receiving the two lines in place.
        report: Run result supplying the composite grade; a missing composite prints n/a.
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
    """Append a hint that points the user at the rule-grouped summary command when the report carries at least the configured number of findings.

    A threshold of zero or less disables the hint. The suggested command quotes each requested path for the shell and drops the trailing space when no
    paths were requested.

    Args:
        lines: Terminal output lines collected for the current analysis journey; receives a blank line, the hint and the suggested command in place.
        report: Run result supplying the hint threshold, the findings to count and the requested paths repeated in the suggested command.

    Returns:
        None; appends the hint to lines only when the enabled threshold is reached.
    """
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
    """Append a titled listing with one indented line per path, or nothing when the path list is empty.

    Args:
        lines: Terminal output lines collected for the current analysis journey; receives a blank line, the title and the paths in place.
        title: Section heading printed above the paths, such as Missing paths.
        paths: Paths to list in the order given; an empty tuple suppresses the whole section, heading included.

    Returns:
        None; appends the titled listing to lines only when paths exist.
    """
    if not paths:
        return
    lines.append("")
    lines.append(title)
    for path in paths:
        lines.append(f"  {path}")


def _append_ignored_section(lines: list[str], report: AnalysisReport) -> None:
    """Append the Ignored paths listing, annotating each path with the source and matching pattern that excluded it when the report records them.

    A path with no recorded detail prints bare, and a detail without a pattern prints its source alone. Nothing is appended when no path was ignored.

    Args:
        lines: Terminal output lines collected for the current analysis journey; receives the section in place.
        report: Run result supplying the ignored paths in display order and the per-path details matched to them by path.

    Returns:
        None; appends the listing to lines only when ignored paths exist.
    """
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
    """Append the Config warnings section with one indented line per warning, or nothing when the configuration produced no warnings.

    Args:
        lines: Terminal output lines collected for the current analysis journey; receives the section in place.
        report: Run result whose config warnings are printed verbatim in the order recorded.

    Returns:
        None; appends the section to lines only when warnings exist.
    """
    if not report.config_warnings:
        return
    lines.append("")
    lines.append("Config warnings")
    for warning in report.config_warnings:
        lines.append(f"  {warning}")


def _append_diagnostics(lines: list[str], diagnostics: tuple[RunDiagnostic, ...]) -> None:
    """Append the Diagnostics section, one line per run diagnostic.

    Each line shows the upper-cased type, selected location and message. A file location includes its line when known.
    An empty file path still takes precedence. Only a None file path falls back to the input path. Two None paths omit the location.

    Args:
        lines: Terminal output lines collected for the current analysis journey; receives the section in place.
        diagnostics: Run diagnostics recorded on the report, rendered in order; an empty tuple suppresses the section.

    Returns:
        None; appends the diagnostic section to lines when diagnostics exist.
    """
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
    """Explain the baseline used or generated by this terminal run.
    After generation the report shows how to apply the file. After matching it points out stale rows a reviewer may want to revisit.

    Args:
        lines: Terminal output lines collected for the current analysis journey; receives the section in place.
        report: Run result whose baseline extension supplies the reported fields. A missing baseline leaves lines unchanged.

    Returns:
        None. Appends the section to lines in place when a baseline is present.
    """
    baseline = report.extensions.baseline
    # A scan that skipped baseline handling has no reviewed-count section to display.
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
    # Once the file is written, show the caller how to apply it on the next scan.
    if baseline.generated:
        # The conventional file is discovered automatically. A custom destination needs its path on the next run.
        if baseline.source == "default":
            lines.append(f"  Tip: commit {baseline.path} and rerun `gruff-py analyse` to apply it.")
        else:
            lines.append(f"  Tip: commit {baseline.path} and rerun with `--baseline {shlex.quote(baseline.path)}` to apply it.")
    # Stale rows tell the reviewer which old counts can be reconsidered after a full scan.
    elif baseline.stale_entries:
        lines.append(f"  Tip: regenerate after review with `gruff-py analyse . --generate-baseline={shlex.quote(baseline.path)}`.")


def append_sensitive_exclusions(lines: list[str], report: AnalysisReport) -> None:
    """Show the counts and reasons for findings removed by audited suppressions.
    Both `analyse` and `summary` use this section to explain changes in the visible findings.

    Args:
        lines: Terminal output lines collected for `analyse` or `summary`. An empty list can receive the audit on its own.
        report: Run result whose suppression audit rows supply the counts, scopes and reasons.

    Returns:
        None. Append the audit section in place when at least one suppression removed a finding.
    """
    audit = suppression_audit_text(report.suppressions)
    # A collection containing only zero-match exclusions has no applied suppression to explain here.
    if audit:
        lines.extend(("", "Sensitive exclusions", f"  {audit}"))


def _append_partial_context_caveat(lines: list[str], report: AnalysisReport) -> None:
    """Append the runner's partial-project warning as the user's scan context.

    Args:
        lines: Terminal output lines collected for the current analysis journey.
        report: Run result; a missing caveat means no scan-context claim is shown.

    Returns:
        None; the supplied output list is updated only when a caveat exists.
    """
    # Full-project scans and partial scans without enabled project-wide rules need no caveat.
    if report.partial_context_caveat is None:
        return
    lines.append("")
    lines.append("Scan context")
    lines.append(f"  Caveat: {report.partial_context_caveat}")


def _append_scoring_mode(lines: list[str], report: AnalysisReport) -> None:
    """Append the scoring mode after the Findings section.

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

    The canonical block carries the composite and finding tally; this section shows each pillar's grade and finding count.

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
    # Keep the composite and finding tally in the canonical block so readers see each headline value once.
    # If display filters hid findings, explain that the score and exit code still reflect the full finding set.
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
    """Append the Findings section with one line per finding, or an indented None when the report holds no findings.

    The separator and heading always appear. Each finding uses the shared one-line format and shows a line number when known.

    Args:
        lines: Terminal output lines collected for the current analysis journey; receives the section in place.
        findings: Findings to render in the order given. An empty tuple renders the heading followed by None.

    Returns:
        None. Appends the complete Findings section to lines.
    """
    lines.append("")
    lines.append("Findings")
    if not findings:
        lines.append("  None")
        return
    for finding in findings:
        location = finding.file_path
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        # FAMILY-CONTRACT section 1 specifies the shared row format - [severity] file:line ruleId - message.
        lines.append(f"- [{finding.severity.value}] {location} {finding.rule_id} - {finding.message}")
