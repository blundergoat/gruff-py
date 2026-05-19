from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisReport:
    """Immutable report payload.

    Attributes:
        tool_version: Version that produced the report.
        findings: Stable finding list.
        exit_code: Process exit code.
    """

    tool_version: str
    findings: tuple[str, ...]
    exit_code: int
