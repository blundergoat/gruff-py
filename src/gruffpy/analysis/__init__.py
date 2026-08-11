"""Expose stable analysis report and schema boundaries to calling developers.

Use these exports when an integration consumes a run without reaching into implementation modules.
They connect results and diagnostics to compatible report versions expected by sibling tools.
"""

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.schema import (
    ANALYSIS_SCHEMA_VERSION,
    BASELINE_SCHEMA_VERSION,
    CONFIG_SCHEMA_VERSION,
    HOTSPOT_SCHEMA_VERSION,
)

__all__ = [
    "ANALYSIS_SCHEMA_VERSION",
    "AnalysisReport",
    "BASELINE_SCHEMA_VERSION",
    "CONFIG_SCHEMA_VERSION",
    "HOTSPOT_SCHEMA_VERSION",
    "RunDiagnostic",
]
