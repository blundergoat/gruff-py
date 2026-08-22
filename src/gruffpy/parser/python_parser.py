"""Reads source files from disk and turns them into ``AnalysisUnit`` objects."""

import ast

from gruffpy.config.analysis_config import DeepScanBudget
from gruffpy.parser.analysis_unit import AnalysisUnit, ParseDiagnostic
from gruffpy.source.source_file import SourceFile


class PythonFileParser:
    """Read source files and parse Python files into analysis units."""

    def parse(
        self,
        source_file: SourceFile,
        budget: DeepScanBudget | None = None,
    ) -> AnalysisUnit:
        """Parse a source file into an analysis unit.

        Args:
            source_file: Source file descriptor to read and parse.
            budget: Effective line/byte bound for Python AST construction.

        Returns:
            Analysis unit with source text, optional AST, and parse diagnostics.
        """
        try:
            with open(source_file.absolute_path, "rb") as f:
                source_bytes = f.read()
        except OSError as exc:
            return AnalysisUnit(
                file=source_file,
                source="",
                tree=None,
                diagnostics=(ParseDiagnostic(message=f"read error: {exc}"),),
            )

        source = source_bytes.decode("utf-8", errors="replace")

        if not source_file.is_python():
            return AnalysisUnit(file=source_file, source=source, tree=None)

        effective_budget = budget or DeepScanBudget()
        line_count = 0 if not source else source.count("\n") + 1
        if effective_budget.enabled and (
            line_count > effective_budget.max_lines
            or len(source_bytes) > effective_budget.max_bytes
        ):
            return AnalysisUnit(
                file=source_file,
                source=source,
                tree=None,
                diagnostics=(
                    ParseDiagnostic(
                        type="bounded-deep-scan",
                        line=1,
                        non_fatal=True,
                        message=(
                            f"path={source_file.display_path}; lines={line_count}; "
                            f"bytes={len(source_bytes)}; maxLines={effective_budget.max_lines}; "
                            f"maxBytes={effective_budget.max_bytes}; "
                            f"override={effective_budget.override}. Text-level rules "
                            "(size, sensitive-data, config) still ran; masking, block parsing, "
                            "AST walking, and other deep script analysis were skipped."
                        ),
                    ),
                ),
            )

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
            child.parent = node  # type: ignore[attr-defined]  # AST parent links
