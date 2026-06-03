"""Renders an AnalysisReport as ``gruff.analysis.v2`` JSON."""

import json
import math
from typing import Any

from gruffpy.analysis.report import AnalysisReport


class JsonReporter:
    """Renders an AnalysisReport to JSON.

    Matches gruff-php's `json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)`
    output: 4-space indent, ASCII-escaped non-ASCII, slashes NOT escaped.
    """

    def render(self, report: AnalysisReport) -> str:
        """Render *report* as the ``gruff.analysis.v2`` JSON document.

        Output is byte-compatible with gruff-php - 4-space indent,
        ASCII-escaped non-ASCII, unescaped forward slashes. Finite floats
        with integer values are coerced to ``int`` so PHP's looser JSON
        rules don't break consumers.

        Args:
            report: Fully-populated analysis report.

        Returns:
            Pretty-printed JSON document with a trailing newline.
        """
        return json.dumps(_php_json_value(report.to_dict()), indent=4) + "\n"


def _php_json_value(value: Any) -> Any:
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: _php_json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_php_json_value(item) for item in value]
    return value
