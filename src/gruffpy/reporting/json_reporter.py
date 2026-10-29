"""Serializes an :class:`AnalysisReport` into canonical v3 JSON text.

Owns the byte-for-byte JSON projection of an analysis run - 4-space indent,
ASCII-escaped non-ASCII, and unescaped forward slashes - so this port emits
documents identical to gruff-php and the other siblings. The rendering contract
and its float-coercion rules live on :class:`JsonReporter` below.
"""

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
        """Render *report* as the ``gruff.analysis.v3`` JSON document.

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

    def render_summary(self, report: AnalysisReport) -> str:
        """Render the exact findings-free ``gruff.summary.v3`` projection.

        Args:
            report: Fully-populated canonical analysis report.

        Returns:
            Pretty-printed summary projection with a trailing newline.
        """
        return json.dumps(_php_json_value(report.to_summary_dict()), indent=4) + "\n"


def _php_json_value(value: Any) -> Any:
    """Turn every finite integral float in a report projection into an int, matching gruff-php's JSON output.

    json.dumps then writes such values without a trailing .0, the way gruff-php does. Dicts and lists are rebuilt rather than mutated, and dict keys
    are kept as they are. Tuples come back as lists. Non-finite floats, floats with a fractional part, and all other scalars pass through unchanged.

    Args:
        value: A projection from AnalysisReport.to_dict or AnalysisReport.to_summary_dict, or any value nested inside one, seen during the recursive
            walk.

    Returns:
        A structure of the same shape in which dicts and lists are new containers, tuples become lists, and integral finite floats become ints; every
        other leaf value is the input object itself.
    """
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: _php_json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_php_json_value(item) for item in value]
    return value
