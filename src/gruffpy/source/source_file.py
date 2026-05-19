"""Lightweight handle for a discovered source file (path + classification)."""

from dataclasses import dataclass
from typing import Literal

SourceFileType = Literal["python", "text"]


@dataclass(frozen=True, slots=True)
class SourceFile:
    absolute_path: str
    display_path: str
    type: SourceFileType = "python"

    def is_python(self) -> bool:
        """Return whether this source file is Python (vs. a text-only source like ``.env``).

        Used by rules and the parser to skip AST-based analysis on plain-text
        files while still letting ``SourceTextRule``-based rules run.

        Returns:
            True when the file is classified as Python source.
        """
        return self.type == "python"
