"""Publish the compact `gruff-py.hotspot.v1` report.

Automation can use `analyse --format hotspot` to prioritise files with the highest finding penalties.
The report also carries suppression audit rows when the scan produces them.
"""

import json

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.schema import HOTSPOT_SCHEMA_VERSION


class HotspotReporter:
    """Render the scan as a JSON list of files to review first.

    Consumers can present files ranked by finding penalties and show the severity counts alongside them.
    The renderer uses the completed report and includes the suppression audit when present.
    """

    def render(self, report: AnalysisReport) -> str:
        """Show which files have the highest finding penalties.
        The scope and limitations explain how to interpret the ranking, and suppression rows show which findings were left out.

        Args:
            report: Report supplying diagnostics and optional scores; no score gives empty hotspots and the full-project scope.

        Returns:
            Pretty-printed JSON document with a trailing newline.
        """
        score = report.score
        payload = {
            "schemaVersion": HOTSPOT_SCHEMA_VERSION,
            "type": "hotspot-map",
            "limitations": (
                "v0.1 hotspot ranking uses finding density and available metrics; "
                "git churn weighting is not available until a later history layer provides it."
            ),
            "scope": score.scope if score is not None else "full-project",
            "diagnostics": [diagnostic.to_dict() for diagnostic in report.diagnostics],
            "hotspots": [] if score is None else [item.to_dict() for item in score.top_offenders],
        }
        # Consumers can explain a ranking that excluded findings using the same audit rows as the full report.
        if report.suppressions:
            payload["suppressions"] = [row.to_dict() for row in report.suppressions]
        return json.dumps(payload, indent=4) + "\n"
