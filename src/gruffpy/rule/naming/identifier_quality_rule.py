"""Placeholder/generic identifier patterns.

Flags names that signal "I'll rename this later" — ``temp``, ``temp1``,
``foo``, ``bar``, ``baz``, ``result1``, ``data2``, ``thing``, ``stuff``.

Detection uses the identifier tokenizer:

- Token ``temp`` / ``foo`` / ``bar`` / ``baz`` / ``qux`` / ``thing`` / ``stuff``
  appearing as the first token (case-insensitive).
- Token ``result`` / ``data`` / ``value`` / ``item`` followed by a numeric
  token (e.g. ``result1``, ``data42``).
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule

_PLACEHOLDER_TOKENS: frozenset[str] = frozenset(
    {"temp", "foo", "bar", "baz", "qux", "thing", "stuff", "todo"}
)
_NUMBERED_BASES: frozenset[str] = frozenset({"result", "data", "value", "item", "var", "x"})


class IdentifierQualityRule(Rule):
    ID = "naming.identifier-quality"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Identifier quality",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        for node in ast.walk(unit.tree):
            for name, lineno in _identifiers_in(node):
                if (name, lineno) in seen:
                    continue
                pattern = _placeholder_pattern(name)
                if pattern is None:
                    continue
                seen.add((name, lineno))
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=f"Identifier {name!r} is a placeholder ({pattern}).",
                        file_path=unit.file.display_path,
                        line=lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=lineno,
                        symbol=name,
                        remediation=("Rename to something descriptive of the value or role."),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"identifier": name, "pattern": pattern},
                    ),
                )
        return findings


def _placeholder_pattern(name: str) -> str | None:
    if name.startswith("__") and name.endswith("__"):
        return None
    tokens = lower_tokens(name)
    if not tokens:
        return None
    first = tokens[0]
    if first in _PLACEHOLDER_TOKENS:
        return f"placeholder token {first!r}"
    # numbered placeholder: result1, data42, value2
    if first in _NUMBERED_BASES and len(tokens) >= 2 and tokens[1].isdigit():
        return f"numbered placeholder {first!r}+{tokens[1]!r}"
    return None


def _identifiers_in(node: ast.AST) -> list[tuple[str, int]]:
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        result: list[tuple[str, int]] = [(node.name, node.lineno)]
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            result.append((arg.arg, arg.lineno))
        return result
    if isinstance(node, ast.ClassDef):
        return [(node.name, node.lineno)]
    if isinstance(node, ast.Assign):
        out: list[tuple[str, int]] = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                out.append((target.id, target.lineno))
            elif isinstance(target, ast.Tuple | ast.List):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        out.append((elt.id, elt.lineno))
        return out
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [(node.target.id, node.target.lineno)]
    return []
