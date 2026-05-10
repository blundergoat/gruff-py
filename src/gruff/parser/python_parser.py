import ast

from gruff.parser.analysis_unit import AnalysisUnit, ParseDiagnostic
from gruff.source.source_file import SourceFile


class PythonFileParser:
    def parse(self, source_file: SourceFile) -> AnalysisUnit:
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

        _attach_parents(tree)
        return AnalysisUnit(file=source_file, source=source, tree=tree)


def _attach_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]
