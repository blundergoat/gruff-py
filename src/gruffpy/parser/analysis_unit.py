"""The parsed-source bundle (AST + diagnostics) that rules receive as input."""

import ast
from dataclasses import dataclass

from gruffpy.source.source_file import SourceFile


@dataclass(frozen=True, slots=True)
class ParseDiagnostic:
    """Parse-time diagnostic attached to an analysis unit."""

    message: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class AnalysisUnit:
    """Source file plus parsed AST and diagnostics supplied to rules."""

    file: SourceFile
    source: str
    tree: ast.AST | None
    diagnostics: tuple[ParseDiagnostic, ...] = ()

    def has_parse_errors(self) -> bool:
        """Return whether parsing produced diagnostics.

        Returns:
            True when the unit has one or more parse diagnostics.
        """
        return bool(self.diagnostics)

    def line_count(self) -> int:
        """Return the number of physical source lines.

        Returns:
            Zero for empty source, otherwise newline count plus one.
        """
        if not self.source:
            return 0
        return self.source.count("\n") + 1
