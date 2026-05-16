"""``docs.useless-docstring`` — docstring that just restates the signature.

Heuristic: the docstring summary, after stop-word and generic-verb removal,
contains only tokens that appear in the function name or its parameter names.
Conservative — flags short single-sentence summaries only. Dunder methods are
exempt because constructors and other framework hooks often have one-liners
by convention.
"""

import ast
import re

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
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not is_public(node.name) or is_dunder(node.name):
                continue
            if is_overload_stub(node) or is_property_setter_or_deleter(node):
                continue
            text = extract_docstring(node)
            if text is None:
                continue
            parsed = parse_docstring(text)
            if parsed is None:
                continue
            summary = parsed.summary
            if not summary:
                continue
            if parsed.description or parsed.params or parsed.returns or parsed.raises:
                # The docstring has content beyond a one-line summary — not useless.
                continue

            content_words = _content_words(summary)
            if not content_words or len(content_words) > _MAX_CONTENT_WORDS:
                continue
            name_tokens = set(lower_tokens(node.name))
            param_tokens = {
                tok for name in signature_param_names(node) for tok in lower_tokens(name)
            }
            allowed = name_tokens | param_tokens
            if not all(word in allowed for word in content_words):
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} docstring restates the signature "
                        "without adding intent."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Describe what the function is *for*, not what its identifier already says."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"summary": summary},
                ),
            )
        return findings


def _content_words(summary: str) -> list[str]:
    """Return lowercased non-stop-word tokens from *summary*."""
    return [
        w.lower()
        for w in _WORD_PATTERN.findall(summary)
        if w.lower() not in _STOP_WORDS and len(w) > 1
    ]
