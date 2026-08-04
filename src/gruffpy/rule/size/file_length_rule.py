"""``size.file-length`` - very large files slow navigation and review."""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule


class FileLengthRule(Rule):
    """Flag files whose substantive line count exceeds the configured threshold (default 1000)."""

    ID = "size.file-length"

    def definition(self) -> RuleDefinition:
        """Describe the file-length rule with a configurable line threshold (default 1000).

        Returns:
            Definition under the size pillar; the threshold is configurable via
            a single ``threshold`` plus ``severity``.
        """
        return RuleDefinition(
            id=self.ID,
            name="File length",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=1000,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per file whose substantive line count exceeds the configured threshold.

        Counts substantive lines: blank lines, full-line ``#`` comments, and
        PEP 257 docstrings are free (family ratification, 2026-08-05), so
        required documentation can never push a file over the size bar.
        String literals outside docstring positions are data and still count.

        Args:
            unit: Parsed source file whose line count is checked.
            context: Rule execution context that supplies the threshold.

        Returns:
            Empty list when under threshold; otherwise a single
            file-anchored finding spanning the whole file.
        """
        definition = self.definition()
        settings = context.settings_for(definition)
        line_count = _substantive_line_count(unit.source, unit.tree)
        threshold_match = settings.high_value_threshold_match(line_count)
        if threshold_match is None:
            return []

        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"File has {line_count} substantive lines, "
                    f"above the {threshold_match.severity.value} threshold of "
                    f"{_format_number(threshold_match.threshold)}."
                ),
                file_path=unit.file.display_path,
                line=1,
                severity=threshold_match.severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=unit.line_count(),
                remediation=("Split oversized files or move responsibilities into smaller units."),
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "lines": line_count,
                    "measuredValue": line_count,
                    "threshold": threshold_match.threshold,
                    "thresholdDirection": "above",
                    "thresholdType": threshold_match.severity.value,
                },
            ),
        ]


def _substantive_line_count(source: str, tree: ast.AST | None) -> int:
    """Count lines carrying code or data; blanks, ``#`` comments, and docstrings are free.

    Docstring relief covers the conventional PEP 257 positions only (first
    statement of a module, class, or function body), read from the parsed
    tree, so string literals used as data keep counting. A parse-failed unit
    has no tree and falls back to blank/comment stripping alone.

    Args:
        source: Full source text of the analysed file.
        tree: Parsed AST when available; None for text files or parse failures.

    Returns:
        Number of lines whose stripped text is non-empty, not a ``#`` comment,
        and not part of a docstring.
    """
    docstring_lines = _docstring_line_numbers(tree)
    count = 0
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line_number in docstring_lines:
            continue
        count += 1
    return count


def _docstring_line_numbers(tree: ast.AST | None) -> set[int]:
    """Collect the line numbers covered by PEP 257 docstrings in the parsed tree.

    A docstring sharing its line with the ``def``/``class`` header (one-line
    definitions) is skipped so the header's code line always counts.

    Args:
        tree: Parsed AST, or None when the source did not parse.

    Returns:
        Set of 1-based line numbers occupied by conventional docstrings.
    """
    if tree is None:
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        is_docstring = (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        )
        if not is_docstring:
            continue
        header_line = getattr(node, "lineno", None)
        if header_line is not None and first.lineno == header_line:
            continue
        lines.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
    return lines


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
