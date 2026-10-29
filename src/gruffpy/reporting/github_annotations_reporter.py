"""Renders findings as GitHub Actions workflow annotations."""

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.finding.finding import Finding


class GithubAnnotationsReporter:
    """Render findings as ``::error``/``::warning``/``::notice`` lines for GitHub Actions PRs."""

    def render(self, report: AnalysisReport) -> str:
        """Render *report* as ``::error``/``::warning``/``::notice`` workflow-command lines.

        Each finding becomes one annotation that GitHub Actions surfaces
        inline on PR diffs. Severity maps: ``error`` → ``error``,
        ``warning`` → ``warning``, ``advisory`` → ``notice``.

        Args:
            report: Fully-populated analysis report.

        Returns:
            Annotation lines (empty string when there are no findings).
        """
        lines = [*(_diagnostic_annotation(item) for item in report.diagnostics)]
        lines.extend(_annotation(finding) for finding in report.findings)
        return "" if not lines else "\n".join(lines) + "\n"


def _diagnostic_annotation(diagnostic: RunDiagnostic) -> str:
    """Format one run diagnostic as a GitHub Actions annotation line, so problems with the run itself are reported in the same output as the findings.

    The level is notice only when the diagnostic is explicitly marked as not invalidating the run. When invalidates_run is True or None, the level is
    error. The file property comes first and uses file_path, or path when file_path is None or empty. It is left out only when that chosen value is
    None. The title is the diagnostic type, and the line property is added only when a line is known.

    Args:
        diagnostic: Run diagnostic to render. Its type becomes the annotation title and its message becomes the annotation message.

    Returns:
        A single annotation line without a trailing newline, in the form ::level properties::message, with the properties and message escaped.
    """
    level = "notice" if diagnostic.invalidates_run is False else "error"
    properties = [f"title={_escape_property(diagnostic.type)}"]
    path = diagnostic.file_path or diagnostic.path
    if path is not None:
        properties.insert(0, f"file={_escape_property(path)}")
    if diagnostic.line is not None:
        properties.append(f"line={diagnostic.line}")
    return f"::{level} {','.join(properties)}::{_escape_data(diagnostic.message)}"


def _annotation(finding: Finding) -> str:
    """Format one finding as a GitHub Actions annotation line, mapping advisory severity to the notice level.

    The error and warning severities keep their names. The properties are always file and title, where title is the rule ID. line and endLine are
    added only when the finding has them.

    Args:
        finding: Finding to render. Its file path, rule ID, line range and message fill the annotation, and its severity picks the level.

    Returns:
        A single annotation line without a trailing newline, in the form ::level properties::message, with the properties and message escaped.
    """
    level = {
        "error": "error",
        "warning": "warning",
        "advisory": "notice",
    }[finding.severity.value]
    properties = [
        f"file={_escape_property(finding.file_path)}",
        f"title={_escape_property(finding.rule_id)}",
    ]
    if finding.line is not None:
        properties.append(f"line={finding.line}")
    if finding.end_line is not None:
        properties.append(f"endLine={finding.end_line}")
    return f"::{level} {','.join(properties)}::{_escape_data(finding.message)}"


def _escape_property(value: str) -> str:
    """Percent-encode an annotation property value so it cannot break the comma-separated property list or end it early at a colon.

    The percent sign is encoded first, so the escapes added afterwards are not encoded twice.

    Args:
        value: Raw property text, such as a file path, rule ID or diagnostic type.

    Returns:
        The value with percent, CR, LF, colon and comma characters percent-encoded.
    """
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _escape_data(value: str) -> str:
    """Percent-encode an annotation message so it stays on one line of the workflow command.

    Only the percent sign, carriage return and line feed are encoded. Colons and commas stay as they are because the message comes after the closing
    double colon.

    Args:
        value: Raw message text from a finding or run diagnostic.

    Returns:
        The value with percent, CR and LF characters percent-encoded.
    """
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
