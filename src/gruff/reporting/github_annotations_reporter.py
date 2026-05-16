"""Renders findings as GitHub Actions workflow annotations."""

from gruff.analysis.report import AnalysisReport
from gruff.finding.finding import Finding


class GithubAnnotationsReporter:
    def render(self, report: AnalysisReport) -> str:
        lines = [_annotation(finding) for finding in report.findings]
        return "" if not lines else "\n".join(lines) + "\n"


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
