from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisReport:
    tool_version: str
    findings: tuple[str, ...]
    exit_code: int
