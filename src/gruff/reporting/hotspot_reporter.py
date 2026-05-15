import json

from gruff.analysis.report import AnalysisReport
from gruff.analysis.schema import HOTSPOT_SCHEMA_VERSION


class HotspotReporter:
    def render(self, report: AnalysisReport) -> str:
        score = report.score
        payload = {
            "schemaVersion": HOTSPOT_SCHEMA_VERSION,
            "type": "hotspot-map",
            "limitations": (
                "v0.1 hotspot ranking uses finding density and available metrics; "
                "git churn weighting is not available until a later history layer provides it."
            ),
            "scope": score.scope if score is not None else "full-project",
            "hotspots": [] if score is None else [item.to_dict() for item in score.top_offenders],
        }
        return json.dumps(payload, indent=4) + "\n"
