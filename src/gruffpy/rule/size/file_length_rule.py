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
from gruffpy.rule.size._lines import code_line_numbers, fallback_code_line_count


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

        Counts substantive lines: blank lines, full-line ``#`` comments, PEP 257
        docstrings and decorator lines are free (FAMILY-CONTRACT.md section 12,
        search "Code lines in every line count"), so
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
        line_count = fallback_code_line_count(unit.source) if unit.is_deep_scan_bounded() else _substantive_line_count(unit.source, unit.tree)
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
    """Count the file's code lines; blanks, ``#`` comments, PEP 257 docstrings and decorators are free.

    Uses the code-line set every length rule shares (``code_line_numbers``), so string literals used as data keep
    counting and a parse-failed unit falls back to blank and comment stripping alone.

    Args:
        source: Full source text of the analysed file.
        tree: Parsed AST when available; None for text files or parse failures.

    Returns:
        Number of code lines, as ``code_line_numbers`` counts them.
    """
    return len(code_line_numbers(source, tree))


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
