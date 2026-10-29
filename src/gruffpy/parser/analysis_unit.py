"""The parsed-source bundle (AST + diagnostics) that rules receive as input."""

import ast
from dataclasses import dataclass

from gruffpy.source.source_file import SourceFile


@dataclass(frozen=True, slots=True)
class ParseDiagnostic:
    """Parse-time diagnostic attached to an analysis unit.

    Attributes:
        message: Human-readable explanation shown on every report surface.
        line: Source line the diagnostic points at, or None when it covers the whole file.
        type: Diagnostic class, such as ``parse-error`` or ``bounded-deep-scan``.
        non_fatal: True when analysis continued, so the file still counts as analysed.
    """

    message: str
    line: int | None = None
    type: str = "parse-error"
    non_fatal: bool = False


@dataclass(frozen=True, slots=True)
class AnalysisUnit:
    """Source file plus parsed AST and diagnostics supplied to rules.

    Attributes:
        file: Source file handle being analysed.
        source: Full source text for source-text rules.
        tree: Parsed Python AST, or None for text files and parse failures.
        diagnostics: Parse diagnostics collected for the source.
    """

    file: SourceFile
    source: str
    tree: ast.AST | None
    diagnostics: tuple[ParseDiagnostic, ...] = ()

    def has_parse_errors(self) -> bool:
        """Return whether parsing produced diagnostics.

        Returns:
            True when the unit has one or more parse diagnostics.
        """
        return any(not diagnostic.non_fatal for diagnostic in self.diagnostics)

    def is_deep_scan_bounded(self) -> bool:
        """Return whether this code unit deliberately omitted deep parsing.

        Returns:
            True when a bounded-deep-scan diagnostic was recorded for this unit.
        """
        return any(diagnostic.type == "bounded-deep-scan" for diagnostic in self.diagnostics)

    def line_count(self) -> int:
        """Return the number of physical source lines.

        Returns:
            Zero for empty source, otherwise newline count plus one.
        """
        if not self.source:
            return 0
        return self.source.count("\n") + 1
