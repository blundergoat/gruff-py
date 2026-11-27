"""Read each discovered file before the analyser runs its rules.

Python files can supply an AST to deeper rules. Text files supply the source needed by text checks.
Read failures, syntax errors and budget limits travel with the unit for the report to explain.
"""

import ast

from gruffpy.config.analysis_config import DeepScanBudget
from gruffpy.parser.analysis_unit import AnalysisUnit, ParseDiagnostic
from gruffpy.source.source_file import SourceFile


class PythonFileParser:
    """Turn a discovered source file into input for the analyser's rules.

    Use this parser after discovery has selected the paths for the scan.
    Its diagnostics tell readers when the file could only receive text checks or could not be read.
    """

    def parse(
        self,
        source_file: SourceFile,
        budget: DeepScanBudget | None = None,
    ) -> AnalysisUnit:
        """Read and parse one discovered file into an `AnalysisUnit` for the rule runner.

        Enforces the deep-scan budget so oversized Python files still run fast text rules while recording why AST rules were skipped.

        Args:
            source_file: Discovered source file to read and parse.
            budget: AST construction limits; None applies the default `DeepScanBudget` thresholds.

        Returns:
            AnalysisUnit carrying decoded source and a parent-linked AST when parsed; `tree` is None for non-Python files, budget skips, or errors,
            and read errors also leave `source` empty alongside a fatal diagnostic.
        """
        try:
            with open(source_file.absolute_path, "rb") as source_handle:
                source_bytes = source_handle.read()
        except OSError as exc:
            # For example, a developer deletes or restricts permissions on a file while a scan is running.
            # Omit the OS filename so JSON, SARIF, and hook diagnostics never leak an absolute host checkout path.
            reason = exc.strerror or str(exc).replace(str(source_file.absolute_path), source_file.display_path) or type(exc).__name__
            return AnalysisUnit(
                file=source_file,
                source="",
                tree=None,
                diagnostics=(ParseDiagnostic(message=f"read error: {reason}"),),
            )

        source = source_bytes.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")

        # A YAML or `.env` file still reaches text checks, with no Python syntax diagnostic.
        if not source_file.is_python():
            return AnalysisUnit(file=source_file, source=source, tree=None)

        # A caller without a budget override gets the default depth limits.
        effective_budget = budget or DeepScanBudget()
        # A trailing newline ends the last physical line. It does not create another line to count against the budget.
        line_count = source.count("\n") + (1 if source and not source.endswith("\n") else 0)
        # Files over either limit stay visible to text checks and report which deep checks were skipped.
        if effective_budget.enabled and (line_count > effective_budget.max_lines or len(source_bytes) > effective_budget.max_bytes):
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
            # An unfinished function can still receive text checks. The syntax diagnostic identifies the line to fix.
            return AnalysisUnit(
                file=source_file,
                source=source,
                tree=None,
                diagnostics=(ParseDiagnostic(message=str(exc.msg or "syntax error"), line=exc.lineno),),
            )
        except ValueError as exc:
            # A parser rejection without a source location still needs a file-level diagnostic and a failed scan.
            return AnalysisUnit(
                file=source_file,
                source=source,
                tree=None,
                diagnostics=(ParseDiagnostic(message=str(exc) or "parse error"),),
            )

        _attach_parents(tree)
        return AnalysisUnit(file=source_file, source=source, tree=tree)


def _attach_parents(tree: ast.AST) -> None:
    """Attach parent links so AST checks can walk from a child to its enclosing node.

    Args:
        tree: Parsed tree or subtree whose descendants receive parent references; this pass does not assign the root a parent.

    Returns:
        None; descendants of tree receive parent attributes in place.
    """
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]  # ast.AST has no declared parent attribute; checks use these links.
