"""``docs.useless-docstring`` — docstring without enough useful context.

Heuristics:

- public function summary restates the function name/signature;
- module/class/function summary is too thin after removing generic words.

Conservative — docstrings with a description body or structured Params /
Returns / Raises sections are accepted. Dunder methods are exempt because
constructors and other framework hooks often have one-liners by convention.
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
        "docstring",
        "for",
        "from",
        "get",
        "gets",
        "if",
        "in",
        "into",
        "is",
        "it",
        "method",
        "module",
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
        "thing",
        "to",
        "value",
        "values",
        "with",
    }
)

_MAX_CONTENT_WORDS = 5
_MIN_CONTENT_WORDS = {
    "module": 6,
    "class": 4,
    "function": 4,
}

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
DocstringNode = ast.Module | ast.ClassDef | FunctionNode


@dataclass(frozen=True, slots=True)
class _UselessDocstring:
    node: DocstringNode
    kind: str
    symbol: str
    summary: str
    reason: str


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
            default_options={"min_summary_words": dict(_MIN_CONTENT_WORDS)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        min_words = _min_summary_words(settings.options.get("min_summary_words"))
        return [
            _useless_docstring_finding(unit, definition, candidate)
            for candidate in _useless_docstrings(unit.tree, min_words=min_words)
        ]


def _min_summary_words(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return dict(_MIN_CONTENT_WORDS)
    minimums = dict(_MIN_CONTENT_WORDS)
    for key in minimums:
        configured = value.get(key)
        if isinstance(configured, int) and not isinstance(configured, bool) and configured > 0:
            minimums[key] = configured
    return minimums


def _useless_docstrings(tree: ast.AST, *, min_words: dict[str, int]) -> list[_UselessDocstring]:
    candidates: list[_UselessDocstring] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        candidate = _useless_docstring(node, min_words=min_words)
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _useless_docstring(
    node: DocstringNode,
    *,
    min_words: dict[str, int],
) -> _UselessDocstring | None:
    kind = _docstring_kind(node)
    if kind is None or _should_skip_useless_docstring_check(node):
        return None
    text = extract_docstring(node)
    if text is None:
        return None
    parsed = parse_docstring(text)
    if parsed is None or not parsed.summary:
        return None
    if parsed.description or parsed.params or parsed.returns or parsed.raises:
        return None
    reason = _useless_reason(node, kind, parsed.summary, min_words=min_words)
    if reason is None:
        return None
    return _UselessDocstring(
        node=node,
        kind=kind,
        symbol=_docstring_symbol(node),
        summary=parsed.summary,
        reason=reason,
    )


def _docstring_kind(node: DocstringNode) -> str | None:
    if isinstance(node, ast.Module):
        return "module"
    if isinstance(node, ast.ClassDef):
        return "class"
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return "function"
    return None


def _should_skip_useless_docstring_check(node: DocstringNode) -> bool:
    if isinstance(node, ast.Module):
        return False
    if isinstance(node, ast.ClassDef):
        return is_dunder(node.name)
    return (
        not is_public(node.name)
        or is_dunder(node.name)
        or is_overload_stub(node)
        or is_property_setter_or_deleter(node)
    )


def _useless_reason(
    node: DocstringNode,
    kind: str,
    summary: str,
    *,
    min_words: dict[str, int],
) -> str | None:
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _is_signature_restatement(
        node, summary
    ):
        return "restates the signature without adding intent"
    content_word_count = len(_content_words(summary))
    if content_word_count < min_words[kind]:
        return f"has only {content_word_count} descriptive word(s)"
    return None


def _is_signature_restatement(node: FunctionNode, summary: str) -> bool:
    content_words = _content_words(summary)
    if not content_words or len(content_words) > _MAX_CONTENT_WORDS:
        return False
    allowed = set(lower_tokens(node.name)) | _parameter_tokens(node)
    return all(word in allowed for word in content_words)


def _parameter_tokens(node: FunctionNode) -> set[str]:
    return {token for name in signature_param_names(node) for token in lower_tokens(name)}


def _docstring_symbol(node: DocstringNode) -> str:
    if isinstance(node, ast.Module):
        return "<module>"
    return qualified_symbol(node, parent_chain(node))


def _useless_docstring_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _UselessDocstring,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"{candidate.kind.capitalize()} {candidate.symbol!r} docstring {candidate.reason}."
        ),
        file_path=unit.file.display_path,
        line=_docstring_line(candidate.node),
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=_docstring_end_line(candidate.node),
        symbol=candidate.symbol,
        remediation=(
            "Write a concise open-source-facing docstring that explains purpose, "
            "contract, and any non-obvious behavior."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"summary": candidate.summary, "kind": candidate.kind, "reason": candidate.reason},
    )


def _docstring_line(node: DocstringNode) -> int:
    return getattr(node, "lineno", 1)


def _docstring_end_line(node: DocstringNode) -> int | None:
    return getattr(node, "end_lineno", None)


def _content_words(summary: str) -> list[str]:
    """Return lowercased non-stop-word tokens from *summary*."""
    return [
        w.lower()
        for w in _WORD_PATTERN.findall(summary)
        if w.lower() not in _STOP_WORDS and len(w) > 1
    ]
