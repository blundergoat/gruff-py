"""The parsed-source bundle (AST + diagnostics) that rules receive as input."""

import ast
from dataclasses import dataclass

from gruffpy.source.source_file import SourceFile


@dataclass(frozen=True, slots=True)
class ParseDiagnostic:
    message: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class AnalysisUnit:
    file: SourceFile
    source: str
    tree: ast.AST | None
    diagnostics: tuple[ParseDiagnostic, ...] = ()

    def has_parse_errors(self) -> bool:
        return bool(self.diagnostics)

    def line_count(self) -> int:
        if not self.source:
            return 0
        return self.source.count("\n") + 1
