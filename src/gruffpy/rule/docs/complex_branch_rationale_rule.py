"""``docs.complex-branch-rationale`` — complex branches need context."""

import ast
from typing import Any

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity._walks import body_nodes, iter_functions
from gruffpy.rule.complexity.cognitive_complexity_rule import cognitive_for
from gruffpy.rule.complexity.cyclomatic_complexity_rule import cyclomatic_for
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._comment_scanner import SourceComment, scan_comments
from gruffpy.rule.docs._docstring_parser import extract_docstring, parse_docstring
from gruffpy.rule.docs._helpers import is_public
from gruffpy.rule.docs.useless_docstring_rule import _content_words
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

_RATIONALE_TERMS = frozenset(
    {
        "adr",
        "bug",
        "compat",
        "compatibility",
        "contract",
        "fallback",
        "legacy",
        "protocol",
        "security",
        "standard",
        "workaround",
    }
)
_GENERIC_COMMENT_WORDS = frozenset({"check", "condition", "loop", "try", "branch", "case"})
_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


class ComplexBranchRationaleRule(Rule):
    """Detect complex functions that lack docstring or branch rationale."""

    ID = "docs.complex-branch-rationale"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the complex branch rationale rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Complex branch rationale",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={
                "cyclomatic_warning": 10,
                "cognitive_warning": 15,
                "private_cyclomatic_warning": 15,
                "private_cognitive_warning": 20,
            },
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze complex functions for missing rationale signals.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context with complexity thresholds.

        Returns:
            Findings for complex functions without docstring or branch comments.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        thresholds = _thresholds(settings.options, definition.default_options)
        comments = scan_comments(unit.source)
        findings: list[Finding] = []
        for fn in iter_functions(unit.tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            cyclomatic = cyclomatic_for(fn)
            cognitive = cognitive_for(fn)
            if not _has_threshold_crossing(fn, cyclomatic, cognitive, thresholds):
                continue
            if _has_substantive_docstring(fn):
                continue
            rationale_signals = _branch_rationale_signals(fn, comments)
            if rationale_signals:
                continue
            findings.append(
                _complex_branch_finding(
                    unit,
                    definition,
                    fn,
                    cyclomatic=cyclomatic,
                    cognitive=cognitive,
                    has_docstring=extract_docstring(fn) is not None,
                    rationale_signals=rationale_signals,
                )
            )
        return findings


def _thresholds(
    options: dict[str, Any],
    defaults: dict[str, Any],
) -> dict[str, int]:
    return {
        key: _positive_int(options.get(key, defaults[key]), fallback=int(defaults[key]))
        for key in defaults
    }


def _positive_int(value: Any, *, fallback: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return fallback


def _has_threshold_crossing(
    fn: _FunctionNode,
    cyclomatic: int,
    cognitive: int,
    thresholds: dict[str, int],
) -> bool:
    if is_public(fn.name):
        return (
            cyclomatic > thresholds["cyclomatic_warning"]
            or cognitive > thresholds["cognitive_warning"]
        )
    return (
        cyclomatic > thresholds["private_cyclomatic_warning"]
        or cognitive > thresholds["private_cognitive_warning"]
    )


def _has_substantive_docstring(fn: _FunctionNode) -> bool:
    text = extract_docstring(fn)
    if text is None:
        return False
    parsed = parse_docstring(text)
    if parsed is None or not parsed.summary:
        return False
    if parsed.description or parsed.params or parsed.returns or parsed.raises:
        return True
    return len(_content_words(parsed.summary)) >= 5


def _branch_rationale_signals(
    fn: _FunctionNode,
    comments: tuple[SourceComment, ...],
) -> tuple[str, ...]:
    signals: list[str] = []
    comments_by_line = {comment.line: comment for comment in comments}
    for node in body_nodes(fn):
        if not _is_branch_node(node):
            continue
        line = getattr(node, "lineno", None)
        if not isinstance(line, int):
            continue
        for offset in (1, 2):
            comment = comments_by_line.get(line - offset)
            if comment is None:
                continue
            if _is_rationale_comment(comment.body):
                signals.append(comment.body)
                break
    return tuple(signals)


def _is_branch_node(node: ast.AST) -> bool:
    return isinstance(node, ast.If | ast.For | ast.AsyncFor | ast.While | ast.Try | ast.Match)


def _is_rationale_comment(body: str) -> bool:
    words = _content_words(body)
    if len(words) < 4:
        return False
    if set(words).issubset(_GENERIC_COMMENT_WORDS):
        return False
    return bool(set(words) & _RATIONALE_TERMS) or len(words) >= 7


def _complex_branch_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    fn: _FunctionNode,
    *,
    cyclomatic: int,
    cognitive: int,
    has_docstring: bool,
    rationale_signals: tuple[str, ...],
) -> Finding:
    symbol = qualified_symbol(fn, parent_chain(fn))
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {symbol!r} is complex but lacks a substantive docstring or branch rationale."
        ),
        file_path=unit.file.display_path,
        line=fn.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=fn.end_lineno,
        symbol=symbol,
        remediation=(
            "Extract the branching logic, or add a concise rationale explaining "
            "the compatibility, protocol, or risk boundary."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "cyclomatic": cyclomatic,
            "cognitive": cognitive,
            "hasDocstring": has_docstring,
            "rationaleSignals": list(rationale_signals),
        },
    )
