"""Write GitHub Actions workflow commands for an analysis report.

Use `analyse --format github` to show findings and diagnostics in CI.
Suppression notices give a reviewer the recorded reason and count for findings withheld from the report.
"""

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.suppression_summary import suppression_audit_text
from gruffpy.finding.finding import Finding


class GithubAnnotationsReporter:
    """Present the findings and run notes as GitHub Actions annotations.

    The workflow log can surface findings at their file locations.
    Run diagnostics and suppression notices explain gaps in what the review shows.
    """

    def render(self, report: AnalysisReport) -> str:
        """Publish findings and run diagnostics as GitHub Actions annotations.
        Errors, warnings and advisories appear at their respective levels. A notice records any active suppression audit.

        Args:
            report: Report supplying findings, diagnostics and the optional suppression audit to annotate.

        Returns:
            Annotation lines with a trailing newline, or an empty string when there are no findings, diagnostics or active suppression notices.
        """
        lines = [*(_diagnostic_annotation(item) for item in report.diagnostics)]
        audit = suppression_audit_text(report.suppressions)
        # CI readers still need to see why findings were withheld when the findings list is empty.
        if audit:
            lines.append(f"::notice title=Sensitive exclusions::{_escape_data(audit)}")
        lines.extend(_annotation(finding) for finding in report.findings)
        # A scan with nothing to annotate emits no workflow command.
        return "" if not lines else "\n".join(lines) + "\n"


def _diagnostic_annotation(diagnostic: RunDiagnostic) -> str:
    """Report one run diagnostic as a GitHub Actions annotation alongside findings.

    Use notice only for invalidates_run=False, otherwise error. Prefer nonempty file_path over path; omit file only when the result is None.
    Put file before the type-based title and include line only when known.

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
