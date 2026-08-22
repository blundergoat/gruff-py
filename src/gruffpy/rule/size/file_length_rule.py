"""``size.file-length`` - very large files slow navigation and review."""

import ast
import io
import tokenize

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
        line_count = (
            _fallback_substantive_line_count(unit.source)
            if unit.is_deep_scan_bounded()
            else _substantive_line_count(unit.source, unit.tree)
        )
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
        Number of physical lines covered by code or non-docstring data tokens.
    """
    docstring_spans = _docstring_source_spans(tree, source.splitlines())
    try:
        tokens = tuple(tokenize.generate_tokens(io.StringIO(source).readline))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return _fallback_substantive_line_count(source)

    ignored_types = {
        tokenize.COMMENT,
        tokenize.DEDENT,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
        tokenize.INDENT,
        tokenize.NEWLINE,
        tokenize.NL,
    }
    substantive_lines: set[int] = set()
    for token in tokens:
        if token.type in ignored_types:
            continue
        if token.type == tokenize.ERRORTOKEN and token.string.isspace():
            continue
        if _is_inside_docstring_span(token, docstring_spans):
            continue
        substantive_lines.update(range(token.start[0], token.end[0] + 1))
    return len(substantive_lines)


def _docstring_source_spans(
    tree: ast.AST | None,
    source_lines: list[str],
) -> tuple[tuple[tuple[int, int], tuple[int, int]], ...]:
    """Collect token-compatible source spans for PEP 257 docstrings.

    Args:
        tree: Parsed AST, or None when the source did not parse.
        source_lines: Source without newline terminators, used to normalize byte columns.

    Returns:
        Start/end positions that enclose only conventional docstring tokens.
    """
    if tree is None:
        return ()
    spans: list[tuple[tuple[int, int], tuple[int, int]]] = []
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
        end_line = first.end_lineno or first.lineno
        end_column = first.end_col_offset or first.col_offset
        spans.append(
            (
                (first.lineno, _character_column(source_lines, first.lineno, first.col_offset)),
                (end_line, _character_column(source_lines, end_line, end_column)),
            )
        )
    return tuple(spans)


def _character_column(source_lines: list[str], line_number: int, byte_column: int) -> int:
    """Convert an AST UTF-8 byte column to tokenize's character column.

    Args:
        source_lines: Source without newline terminators.
        line_number: One-based source line containing the offset.
        byte_column: Zero-based UTF-8 byte offset reported by the AST.

    Returns:
        Zero-based Unicode character offset on the same line.
    """
    line = source_lines[line_number - 1]
    return len(line.encode("utf-8")[:byte_column].decode("utf-8"))


def _is_inside_docstring_span(
    token: tokenize.TokenInfo,
    spans: tuple[tuple[tuple[int, int], tuple[int, int]], ...],
) -> bool:
    """Return whether a token belongs to a conventional docstring expression.

    Args:
        token: Token whose physical lines would otherwise count as source.
        spans: Parsed docstring boundaries in tokenize-compatible coordinates.

    Returns:
        True only when the complete token lies inside one docstring expression.
    """
    return any(start <= token.start and token.end <= end for start, end in spans)


def _fallback_substantive_line_count(source: str) -> int:
    """Count parse-failed source when tokenization cannot classify later lines.

    Args:
        source: Invalid or incomplete Python source text.

    Returns:
        Nonblank lines that are not visibly full-line comments.
    """
    count = 0
    for line in source.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            count += 1
    return count


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
