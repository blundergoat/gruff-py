"""Non-finding diagnostics surfaced alongside findings (e.g. parse errors, config notes)."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RunDiagnostic:
    """Non-finding diagnostic emitted for run-level issues."""

    type: str
    message: str
    file_path: str | None = None
    line: int | None = None
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the diagnostic to the analysis report payload.

        Returns:
            JSON-compatible diagnostic mapping.
        """
        return {
            "type": self.type,
            "message": self.message,
            "file": self.file_path,
            "line": self.line,
            "path": self.path,
        }
