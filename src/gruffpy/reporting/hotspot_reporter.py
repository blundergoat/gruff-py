"""Renders an AnalysisReport as a ``gruff-py.hotspot.v1`` JSON hotspot map."""

import json

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.schema import HOTSPOT_SCHEMA_VERSION


class HotspotReporter:
    """Render an analysis report as a ``gruff-py.hotspot.v1`` JSON map of top-offender files."""

    def render(self, report: AnalysisReport) -> str:
        """Render the report as a gruff-py.hotspot.v1 JSON map of top-offender files.

        The limitations field explains ranking by finding density and available metrics without git churn.

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
        return json.dumps(payload, indent=4) + "\n"
