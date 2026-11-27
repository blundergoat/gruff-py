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
from gruffpy.rule.size import _band
from gruffpy.rule.size._band import LIMIT_BAND_KEY, band_advice, banded_severity, limit_band, limit_in_force
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

        The syntax-aware count excludes documentation and decorators under FAMILY-CONTRACT.md section 12, Code lines in every line count.
        Blank and comment-only lines are free. Docstrings and decorators may count in a fallback. String literals used as data count.

        Args:
            unit: Source file to measure. The syntax-aware count may cache its code line numbers on the file's AST.
            context: Rule execution context that supplies the threshold.

        Returns:
            An empty list if no threshold is active or the count is at or below it. Otherwise, one finding spans the file.
        """
        definition = self.definition()
        settings = context.settings_for(definition)
        line_count = fallback_code_line_count(unit.source) if unit.is_deep_scan_bounded() else _substantive_line_count(unit.source, unit.tree)
        threshold_match = settings.high_value_threshold_match(line_count)
        band = limit_band(line_count, limit_in_force(settings))
        if threshold_match is None:
            return []

        return [
            Finding(
                rule_id=definition.id,
                message=f"File has {line_count} substantive lines, above the limit of {_format_number(threshold_match.threshold)}.",
                file_path=unit.file.display_path,
                line=1,
                severity=banded_severity(band, threshold_match.severity),
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=unit.line_count(),
                remediation=band_advice(band, _band.LOWER_FILE, _band.SPLIT_FILE),
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "lines": line_count,
                    "measuredValue": line_count,
                    "threshold": threshold_match.threshold,
                    "thresholdDirection": "above",
                    "thresholdType": threshold_match.severity.value,
                    LIMIT_BAND_KEY: band,
                },
            ),
        ]


def _substantive_line_count(source: str, tree: ast.AST | None) -> int:
    """Count physical code lines for the file-length rule.

    Successful tokenization ignores layout and comments, counts lines inside data strings and uses any AST to exclude docstrings.
    On tokenization failure, skip blanks and full-line comments. In both cases, a supplied AST excludes decorators and caches the line set.

    Args:
        source: Full source text of the analysed file.
        tree: Parsed AST when available; None for text files or parse failures.

    Returns:
        Number of code lines reported by code_line_numbers.
    """
    return len(code_line_numbers(source, tree))


def _format_number(value: int | float) -> str:
    """Render the matched threshold for the finding message, showing whole-number floats without a trailing .0.

    Args:
        value: Threshold value from the matched severity tier; it may be an int or a float, depending on how it was configured.

    Returns:
        Integer text for integers and finite whole-number floats, so 1000.0 renders as 1000. Other floats use their usual Python text.
    """
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
