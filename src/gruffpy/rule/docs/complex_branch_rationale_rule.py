"""``docs.complex-branch-rationale`` - complex branches need context."""

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
from gruffpy.rule.docs._helpers import _content_words, is_public
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
    """Resolve each default option to a positive int threshold, preferring the configured value when it is valid.

    Only the keys present in defaults are resolved; configured keys absent from defaults are ignored.

    Args:
        options: Configured rule options; a key missing here takes its default value before validation.
        defaults: Rule default options; their keys decide which thresholds are returned and their values, cast to int, are the fallbacks for invalid
            configured values.

    Returns:
        Mapping of every default key to its threshold: the configured value when it is a positive int, otherwise the default.
    """
    return {key: _positive_int(options.get(key, defaults[key]), fallback=int(defaults[key])) for key in defaults}


def _positive_int(value: Any, *, fallback: int) -> int:
    """Accept a configured threshold only when it is a positive int, otherwise use the fallback.

    Args:
        value: Candidate threshold, either the configured option value or the default when the option is not configured; bools, non-int values and
            ints below 1 are rejected.
        fallback: Threshold returned when value is rejected.

    Returns:
        value when it is a positive non-bool int, otherwise fallback.
    """
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return fallback


def _has_threshold_crossing(
    fn: _FunctionNode,
    cyclomatic: int,
    cognitive: int,
    thresholds: dict[str, int],
) -> bool:
    """Decide whether either complexity score exceeds the threshold pair that applies to the function's name.

    Names accepted by is_public are compared with cyclomatic_warning and cognitive_warning; every other name, dunder hooks included, is compared with
    private_cyclomatic_warning and private_cognitive_warning.

    Args:
        fn: Function whose name selects the public or private threshold pair.
        cyclomatic: Cyclomatic complexity score of fn.
        cognitive: Cognitive complexity score of fn.
        thresholds: Validated thresholds from _thresholds, keyed by option name.

    Returns:
        True when either score is strictly greater than its threshold in the selected pair.
    """
    if is_public(fn.name):
        return cyclomatic > thresholds["cyclomatic_warning"] or cognitive > thresholds["cognitive_warning"]
    return cyclomatic > thresholds["private_cyclomatic_warning"] or cognitive > thresholds["private_cognitive_warning"]


def _has_substantive_docstring(fn: _FunctionNode) -> bool:
    """Decide whether a function's own docstring carries enough content to exempt the function from this rule.

    A docstring counts when parse_docstring yields a non-empty summary plus any description, parameter, return or raises section. A summary with none
    of those counts only when _content_words finds at least five content words in it.

    Args:
        fn: Function whose docstring is extracted and parsed.

    Returns:
        True when the docstring passes the content test; False when it is absent, parse_docstring returns None, the summary is empty, or a
        summary-only docstring has fewer than five content words.
    """
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
    """Collect the rationale comments found on the two lines above each branch statement in a function body.

    Branch statements are the nodes _is_branch_node accepts from body_nodes, which does not descend into nested functions or classes. For each branch,
    the comment on the line directly above is tried first and then the comment two lines above; the first one that passes _is_rationale_comment is
    collected. A comment on the branch line itself is not considered.

    Args:
        fn: Function whose body is walked for branch statements.
        comments: Comments scanned from the whole source file, matched to branches by line number.

    Returns:
        Bodies of the matched rationale comments, at most one per branch in body_nodes order; an empty tuple means no branch has a rationale comment.
    """
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
    """Identify the statement types whose preceding comments can count as branch rationale.

    Args:
        node: AST node from the function body walk.

    Returns:
        True for if, for, async for, while, try and match statements, except a try with except* handlers; False for any other node.
    """
    return isinstance(node, ast.If | ast.For | ast.AsyncFor | ast.While | ast.Try | ast.Match)


def _is_rationale_comment(body: str) -> bool:
    """Decide whether a comment body says enough to count as branch rationale.

    The body needs at least four content words from _content_words that are not all drawn from _GENERIC_COMMENT_WORDS, and then either one word from
    _RATIONALE_TERMS or at least seven content words.

    Args:
        body: Comment text with the leading marker stripped.

    Returns:
        True when the comment passes those word tests, otherwise False.
    """
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
    """Build the finding for a complex function that lacks a substantive docstring and any branch rationale comment.

    The finding spans the function's def line to its end line, names its qualified symbol in the message, takes severity, pillar, tier, confidence and
    secondary pillars from definition, and records both scores, hasDocstring and rationaleSignals in metadata.

    Args:
        unit: Parsed source file whose display path the finding reports.
        definition: Rule metadata supplying the rule ID, default severity, pillar, tier, confidence and secondary pillars.
        fn: Function that crossed its complexity threshold; supplies the reported line span and qualified symbol.
        cyclomatic: Cyclomatic complexity score recorded as cyclomatic in metadata.
        cognitive: Cognitive complexity score recorded as cognitive in metadata.
        has_docstring: Whether the function has any docstring at all, recorded as hasDocstring; True means a docstring exists but did not count as
            substantive.
        rationale_signals: Rationale comment bodies recorded as the rationaleSignals list in metadata.

    Returns:
        Finding for fn carrying the rule's message, remediation and complexity metadata.
    """
    symbol = qualified_symbol(fn, parent_chain(fn))
    return Finding(
        rule_id=definition.id,
        message=(f"Function {symbol!r} is complex but lacks a substantive docstring or branch rationale."),
        file_path=unit.file.display_path,
        line=fn.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=fn.end_lineno,
        symbol=symbol,
        remediation=("Extract the branching logic, or add a concise rationale explaining the compatibility, protocol, or risk boundary."),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "cyclomatic": cyclomatic,
            "cognitive": cognitive,
            "hasDocstring": has_docstring,
            "rationaleSignals": list(rationale_signals),
        },
    )
