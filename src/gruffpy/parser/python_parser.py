"""Reads source files from disk and turns them into ``AnalysisUnit`` objects."""

import ast

from gruffpy.parser.analysis_unit import AnalysisUnit, ParseDiagnostic
from gruffpy.source.source_file import SourceFile


class PythonFileParser:
    """Read source files and parse Python files into analysis units."""

    def parse(self, source_file: SourceFile) -> AnalysisUnit:
        """Parse a source file into an analysis unit.

        Args:
            source_file: Source file descriptor to read and parse.

        Returns:
            Analysis unit with source text, optional AST, and parse diagnostics.
        """
        try:
            with open(source_file.absolute_path, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError as exc:
            return AnalysisUnit(
                file=source_file,
                source="",
                tree=None,
                diagnostics=(ParseDiagnostic(message=f"read error: {exc}"),),
            )

        if not source_file.is_python():
            return AnalysisUnit(file=source_file, source=source, tree=None)

        try:
            tree = ast.parse(source, filename=source_file.display_path)
        except SyntaxError as exc:
            return AnalysisUnit(
                file=source_file,
                source=source,
                tree=None,
                diagnostics=(
                    ParseDiagnostic(message=str(exc.msg or "syntax error"), line=exc.lineno),
                ),
            )
        except ValueError as exc:
            return AnalysisUnit(
                file=source_file,
                source=source,
                tree=None,
                diagnostics=(ParseDiagnostic(message=str(exc) or "parse error"),),
            )

        _attach_parents(tree)
        return AnalysisUnit(file=source_file, source=source, tree=tree)


def _attach_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]
