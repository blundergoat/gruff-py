from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RunDiagnostic:
    type: str
    message: str
    file_path: str | None = None
    line: int | None = None
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "message": self.message,
            "file": self.file_path,
            "line": self.line,
            "path": self.path,
        }
