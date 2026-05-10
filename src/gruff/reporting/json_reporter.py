import json

from gruff.analysis.report import AnalysisReport


class JsonReporter:
    """Renders an AnalysisReport to JSON.

    Matches gruff-php's `json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)`
    output: 4-space indent, ASCII-escaped non-ASCII, slashes NOT escaped.
    """

    def render(self, report: AnalysisReport) -> str:
        return json.dumps(report.to_dict(), indent=4) + "\n"
