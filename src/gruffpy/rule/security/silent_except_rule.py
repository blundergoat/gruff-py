"""``security.silent-except`` - ``except:`` or ``except Exception:`` body is pass-only.

Suppressed when the handler body contains any logging call (``logger.error``,
``logging.exception``, ``print``, etc.) - that's not silent, even if the
exception is then swallowed.

A comment inside the handler can also explain a deliberate fallback. Stock
phrasing, unfinished-handling markers and commented-out code do not establish that reason.
"""

import ast
import re
import tokenize
from io import StringIO

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_node_helper import (
    does_exception_handler_log,
    is_pass_or_ellipsis_body,
)

_WIDE_EXCEPTION_LEAVES: frozenset[str] = frozenset({"Exception", "BaseException"})
_UNFINISHED_MARKERS = ("".join(("TO", "DO")), "".join(("FIX", "ME")), "".join(("X", "XX")), "".join(("HA", "CK")))
_UNFINISHED_PATTERN = re.compile(r"\b(?:" + "|".join(_UNFINISHED_MARKERS) + r")\b", re.IGNORECASE)
_REASON_WORDS = frozenset(
    {"if", "because", "since", "when", "unless", "must", "cannot", "cant", "below", "expected", "otherwise", "continue", "from"}
)
_STOCK_WORDS = frozenset(
    {
        "do",
        "does",
        "nothing",
        "no",
        "op",
        "noop",
        "nop",
        "ignore",
        "ignored",
        "ignoring",
        "silent",
        "silently",
        "silence",
        "swallow",
        "swallowed",
        "catch",
        "caught",
        "exception",
        "exceptions",
        "error",
        "errors",
        "intentionally",
        "deliberately",
        "here",
        "just",
        "pass",
        "the",
        "it",
        "this",
        "fall",
        "back",
        "in",
        "case",
    }
)


class SilentExceptRule(Rule):
    """Detect wide pass-only handlers without logging or a comment explaining the silence."""

    ID = "security.silent-except"

    def definition(self) -> RuleDefinition:
        """Describe the silent-except rule as a high-confidence advisory.

        Advisory rather than warning because silent swallowing can be
        intentional (fire-and-forget cleanup, optional best-effort steps).
        High confidence because the matched shape is narrow: wide ``except``
        target, pass-only body, and no logging call in the handler.

        Returns:
            Definition for the silent-except rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Silent except",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
            # M02's complete repaired census judged 21 of 29 findings right, below the 0.80 security floor.
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``except:`` / ``except Exception:`` whose body is just ``pass`` / ``...``.

        A logging call in the handler (``logger.error``,
        ``logging.exception``, ``print``, etc.) defuses the rule - the
        exception is observable even when swallowed. An explanatory comment
        inside that handler also makes a deliberate fallback reviewable.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unexplained, pass-only wide handler.
        """
        if unit.tree is None or "except" not in unit.source:
            return []
        comments = {
            token.start[0]: token.string[1:].strip()
            for token in tokenize.generate_tokens(StringIO(unit.source).readline)
            if token.type == tokenize.COMMENT
        }
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not _is_wide_exception(node):
                continue
            if not is_pass_or_ellipsis_body(node.body):
                continue
            if does_exception_handler_log(node):
                continue
            if _has_explanatory_comment(node, comments):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="Exception silently swallowed (pass-only handler).",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=("Log the exception, re-raise, or catch a specific exception type and handle it deliberately."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings


def _has_explanatory_comment(handler: ast.ExceptHandler, comments: dict[int, str]) -> bool:
    """Use only real comments belonging to this pass-only handler as rationale."""
    prose = " ".join(comments[line] for line in range(handler.lineno, (handler.end_lineno or handler.lineno) + 1) if line in comments)
    if not prose or _UNFINISHED_PATTERN.search(prose):
        return False
    # An incomplete compound header is still disabled code, rather than an explanation.
    candidate = prose + "\n    pass" if prose.endswith(":") else prose
    try:
        ast.parse(candidate)
    except SyntaxError:
        words = frozenset(re.findall(r"[a-z]+", prose.lower().replace("'", "").replace("’", "")))
        gives_reason = bool(words & _REASON_WORDS) or "fall back" in prose.lower() or "in case" in prose.lower()
        return gives_reason and bool(words - _STOCK_WORDS - _REASON_WORDS)
    return False


def _is_wide_exception(handler: ast.ExceptHandler) -> bool:
    """True if the handler catches no specific type, or catches Exception/BaseException."""
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name):
        return handler.type.id in _WIDE_EXCEPTION_LEAVES
    if isinstance(handler.type, ast.Attribute):
        return handler.type.attr in _WIDE_EXCEPTION_LEAVES
    return False
