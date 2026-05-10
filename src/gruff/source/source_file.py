from dataclasses import dataclass
from typing import Literal

SourceFileType = Literal["python", "text"]


@dataclass(frozen=True, slots=True)
class SourceFile:
    absolute_path: str
    display_path: str
    type: SourceFileType = "python"

    def is_python(self) -> bool:
        return self.type == "python"
