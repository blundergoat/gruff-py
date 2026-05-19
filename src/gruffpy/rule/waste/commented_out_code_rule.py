"""Comment lines that parse as Python code.

Two-stage heuristic:

1. A cheap regex pre-filter rejects most comment styles ("TODO:", english
   prose, license headers, etc.) without invoking the parser.
2. Remaining candidates go through ``ast.parse`` — if the parser accepts
   them, the comment is flagged.

Confidence: LOW. False positives are easy on prose comments that happen to
look like valid Python (``# x is the same as y``). Use the per-rule
suppression knob (TBD) when needed.
"""

import ast
import re

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

# Pre-filter: must look like a statement-or-assignment-or-call before we
# bother running the compiler.
_CODE_LIKE = re.compile(
    r"""^\s*\#\s*
    (
        # `x = expr` / `x += expr` / etc.
        [A-Za-z_][\w.]*\s*[+\-*/%&|^]?=\s*\S
        |
        # `name(...)` call
        [A-Za-z_][\w.]*\(\S
        |
        # `if cond:` / `for x in y:` / `while cond:` / `return expr`
        (?:return|raise|yield|assert|if|elif|while|for|with|try|except|finally|break|continue|pass)\b
        |
        # `print x` or `import x` style
        (?:import|from)\b
    )
    """,
    re.VERBOSE,
)

# Comments to skip even if they look code-like
_SKIP_PATTERNS = (
    re.compile(r"^\s*#\s*(TODO|FIXME|XXX|HACK|NOTE|TBD)\b", re.IGNORECASE),
    re.compile(r"^\s*#\s*type\s*:", re.IGNORECASE),
    re.compile(r"^\s*#\s*pragma\s*:", re.IGNORECASE),
    re.compile(r"^\s*#\s*noqa\b", re.IGNORECASE),
    re.compile(r"^\s*#\s*pylint\b", re.IGNORECASE),
    re.compile(r"^\s*#!/", re.IGNORECASE),
    re.compile(r"^\s*#\s*coding[:=]", re.IGNORECASE),
)


class CommentedOutCodeRule(Rule):
    """Detect comment lines that pass `ast.parse` after the code-like pre-filter accepts them."""

    ID = "waste.commented-out-code"

    def definition(self) -> RuleDefinition:
        """Describe the commented-out-code rule as a low-confidence advisory.

        Low confidence reflects the parser-based heuristic — prose comments
        that happen to look like Python (``# x is the same as y``) can trip it.

        Returns:
            Definition for the commented-out-code rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Commented-out code",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan each source line for comments that parse as Python statements.

        Lines matching ``TODO``/``FIXME``/``type:``/``pragma:``/``noqa``/etc.
        are skipped before the parser runs, so the regex pre-filter only
        forwards statement-shaped candidates.

        Args:
            unit: Parsed source file (only ``unit.source`` is used here).
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per line whose comment body re-parses as Python code.
        """
        if not unit.source:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for lineno, line in enumerate(unit.source.splitlines(), start=1):
            if any(p.search(line) for p in _SKIP_PATTERNS):
                continue
            if not _CODE_LIKE.search(line):
                continue
            candidate = _strip_comment_prefix(line)
            if not _is_valid_python(candidate):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Commented-out code on line {lineno}.",
                    file_path=unit.file.display_path,
                    line=lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=lineno,
                    remediation="Delete the comment or convert it to prose if it's documentation.",
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": candidate.strip()[:80]},
                ),
            )
        return findings


def _strip_comment_prefix(line: str) -> str:
    """Return *line* with the leading ``#`` and at most one space stripped,
    preserving original indentation so ``compile`` sees consistent levels."""
    idx = line.find("#")
    if idx < 0:
        return line
    indent = line[:idx]
    body = line[idx + 1 :]
    if body.startswith(" "):
        body = body[1:]
    return indent + body


def _is_valid_python(candidate: str) -> bool:
    """Return True if *candidate* parses as Python (top-level or function-body)."""
    dedented = candidate.lstrip()
    if not dedented:
        return False
    # Try top-level first; if it fails, wrap in a function so `return`,
    # `yield`, `continue`, `break` parse too.
    for wrap in (dedented, f"def __probe__():\n    {dedented}"):
        try:
            ast.parse(wrap + "\n")
        except (SyntaxError, ValueError):
            continue
        return True
    return False
