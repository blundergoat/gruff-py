"""Describe run problems that are separate from source-code findings.

Use this module when parsing, configuration, or path handling prevents a normal analysis result.
Reporters place these diagnostics beside findings so users can correct the run itself first.
"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RunDiagnostic:
    """Represent one actionable problem with the analysis run itself.

    Use when the caller needs to report a parse, config, or requested-path failure.
    Optional locations let reporters point to a file when one caused the problem.

    Attributes:
        type: Diagnostic category such as ``parse-error``.
        message: Human-readable diagnostic text.
        file_path: Optional file path associated with the diagnostic.
        line: Optional one-based source line.
        path: Optional input path associated with the diagnostic.
        invalidates_run: False for an informational degradation that must not
            force exit code 2; None preserves the legacy fatal default.
    """

    type: str
    message: str
    file_path: str | None = None
    line: int | None = None
    path: str | None = None
    invalidates_run: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return this run problem in the stable report payload shape.

        Use when a JSON-capable reporter prepares diagnostics for the caller.

        Returns:
            JSON-compatible mapping; absent locations remain null for a run-wide problem.
        """
        payload = {
            "type": self.type,
            "message": self.message,
            "file": self.file_path,
            "line": self.line,
            "path": self.path,
        }
        if self.invalidates_run is not None:
            payload["invalidatesRun"] = self.invalidates_run
        return payload
