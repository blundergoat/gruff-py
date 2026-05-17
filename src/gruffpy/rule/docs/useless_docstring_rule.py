"""``docs.useless-docstring`` — docstring that just restates the signature.

Heuristic: the docstring summary, after stop-word and generic-verb removal,
contains only tokens that appear in the function name or its parameter names.
Conservative — flags short single-sentence summaries only. Dunder methods are
exempt because constructors and other framework hooks often have one-liners
by convention.
"""

import ast
import re
from dataclasses import dataclass

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import is_overload_stub
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._docstring_parser import extract_docstring, parse_docstring
from gruffpy.rule.docs._helpers import (
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
    signature_param_names,
)
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

_WORD_PATTERN = re.compile(r"[A-Za-z]+")

# Stop words and generic verbs that don't carry signal when comparing summaries
# against function names. Lowercased.
_STOP_WORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "and",
        "as",
        "at",
        "be",
        "by",
        "do",
        "does",
        "for",
        "from",
        "get",
        "gets",
        "if",
        "in",
        "into",
        "is",
        "it",
        "of",
        "on",
        "or",
        "perform",
        "return",
        "returns",
        "run",
        "runs",
        "set",
        "sets",
        "that",
        "the",
        "this",
        "to",
        "value",
        "values",
        "with",
    }
)

_MAX_CONTENT_WORDS = 5

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class _UselessDocstring:
    node: FunctionNode
    symbol: str
    summary: str


class UselessDocstringRule(Rule):
    ID = "docs.useless-docstring"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Useless docstring",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        return [
            _useless_docstring_finding(unit, definition, candidate)
            for candidate in _useless_docstrings(unit.tree)
        ]


def _useless_docstrings(tree: ast.AST) -> list[_UselessDocstring]:
    candidates: list[_UselessDocstring] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        summary = _useless_summary(node)
        if summary is not None:
            candidates.append(
                _UselessDocstring(
                    node=node,
                    symbol=qualified_symbol(node, parent_chain(node)),
                    summary=summary,
                )
            )
    return candidates


def _useless_summary(node: FunctionNode) -> str | None:
    if _should_skip_useless_docstring_check(node):
        return None
    text = extract_docstring(node)
    if text is None:
        return None
    parsed = parse_docstring(text)
    if parsed is None or not parsed.summary:
        return None
    if parsed.description or parsed.params or parsed.returns or parsed.raises:
        return None
    if _is_signature_restatement(node, parsed.summary):
        return parsed.summary
    return None


def _should_skip_useless_docstring_check(node: FunctionNode) -> bool:
    return (
        not is_public(node.name)
        or is_dunder(node.name)
        or is_overload_stub(node)
        or is_property_setter_or_deleter(node)
    )


def _is_signature_restatement(node: FunctionNode, summary: str) -> bool:
    content_words = _content_words(summary)
    if not content_words or len(content_words) > _MAX_CONTENT_WORDS:
        return False
    allowed = set(lower_tokens(node.name)) | _parameter_tokens(node)
    return all(word in allowed for word in content_words)


def _parameter_tokens(node: FunctionNode) -> set[str]:
    return {token for name in signature_param_names(node) for token in lower_tokens(name)}


def _useless_docstring_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _UselessDocstring,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {candidate.symbol!r} docstring restates the signature "
            "without adding intent."
        ),
        file_path=unit.file.display_path,
        line=candidate.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=candidate.node.end_lineno,
        symbol=candidate.symbol,
        remediation=("Describe what the function is *for*, not what its identifier already says."),
        secondary_pillars=definition.secondary_pillars,
        metadata={"summary": candidate.summary},
    )


def _content_words(summary: str) -> list[str]:
    """Return lowercased non-stop-word tokens from *summary*."""
    return [
        w.lower()
        for w in _WORD_PATTERN.findall(summary)
        if w.lower() not in _STOP_WORDS and len(w) > 1
    ]
