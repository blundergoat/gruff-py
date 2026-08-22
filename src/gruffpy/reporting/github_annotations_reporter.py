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
    level = "notice" if diagnostic.invalidates_run is False else "error"
    properties = [f"title={_escape_property(diagnostic.type)}"]
    path = diagnostic.file_path or diagnostic.path
    if path is not None:
        properties.insert(0, f"file={_escape_property(path)}")
    if diagnostic.line is not None:
        properties.append(f"line={diagnostic.line}")
    return f"::{level} {','.join(properties)}::{_escape_data(diagnostic.message)}"


def _annotation(finding: Finding) -> str:
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
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
