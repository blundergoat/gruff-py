"""Placeholder/generic identifier patterns.

Flags names that signal "I'll rename this later" - ``temp``, ``temp1``,
``foo``, ``bar``, ``baz``, ``result1``, ``data2``, ``thing``, ``stuff``,
``todo``.

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
    {"temp", "foo", "bar", "baz", "qux", "thing", "stuff"}
)
_EXACT_PLACEHOLDER_TOKENS: frozenset[str] = frozenset({"todo"})
_NUMBERED_BASES: frozenset[str] = frozenset({"result", "data", "value", "item", "var", "x"})


class IdentifierQualityRule(Rule):
    """Detect placeholder identifiers like `temp`/`foo`/`bar` or numbered names like `result1`."""

    ID = "naming.identifier-quality"

    def definition(self) -> RuleDefinition:
        """Describe the identifier-quality rule as a high-confidence warning.

        High confidence because the matched tokens (``temp``, ``foo``,
        ``bar``, numbered ``result1``, etc.) are placeholder-only - there
        are essentially no legitimate domain uses, so false positives are
        rare.

        Returns:
            Definition for the identifier-quality rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Identifier quality",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag identifiers that match placeholder patterns left over from drafts.

        Three families of pattern: exact ``todo`` matches; first-token
        ``temp``/``foo``/``bar``/``baz``/``qux``/``thing``/``stuff``; and
        numbered placeholders (``result1``, ``data42``, ``value2``). Each
        unique ``(name, line)`` fires once.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per placeholder identifier (variable, parameter,
            function, or class).
        """
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
                    _finding_for_identifier(
                        definition,
                        unit.file.display_path,
                        name,
                        lineno,
                        pattern,
                    )
                )
        return findings


def _finding_for_identifier(
    definition: RuleDefinition,
    file_path: str,
    name: str,
    lineno: int,
    pattern: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=f"Identifier {name!r} is a placeholder ({pattern}).",
        file_path=file_path,
        line=lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=lineno,
        symbol=name,
        remediation="Rename to something descriptive of the value or role.",
        secondary_pillars=definition.secondary_pillars,
        metadata={"identifier": name, "pattern": pattern},
    )


def _placeholder_pattern(name: str) -> str | None:
    if name.startswith("__") and name.endswith("__"):
        return None
    tokens = lower_tokens(name)
    if not tokens:
        return None
    if _is_exact_placeholder(tokens) or _has_placeholder_prefix(tokens):
        return f"placeholder token {tokens[0]!r}"
    # numbered placeholder: result1, data42, value2
    if _is_numbered_placeholder(tokens):
        return f"numbered placeholder {tokens[0]!r}+{tokens[1]!r}"
    return None


def _is_exact_placeholder(tokens: list[str]) -> bool:
    return len(tokens) == 1 and tokens[0] in _EXACT_PLACEHOLDER_TOKENS


def _has_placeholder_prefix(tokens: list[str]) -> bool:
    return tokens[0] in _PLACEHOLDER_TOKENS


def _is_numbered_placeholder(tokens: list[str]) -> bool:
    return len(tokens) >= 2 and tokens[0] in _NUMBERED_BASES and tokens[1].isdigit()


def _identifiers_in(node: ast.AST) -> list[tuple[str, int]]:
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return [(node.name, node.lineno), *_argument_identifiers(node.args)]
    if isinstance(node, ast.ClassDef):
        return [(node.name, node.lineno)]
    if isinstance(node, ast.Assign):
        return _assignment_identifiers(node.targets)
    if isinstance(node, ast.AnnAssign):
        return _target_identifiers(node.target)
    return []


def _argument_identifiers(arguments: ast.arguments) -> list[tuple[str, int]]:
    all_args = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    return [(arg.arg, arg.lineno) for arg in all_args]


def _assignment_identifiers(targets: list[ast.expr]) -> list[tuple[str, int]]:
    identifiers: list[tuple[str, int]] = []
    for target in targets:
        identifiers.extend(_target_identifiers(target))
    return identifiers


def _target_identifiers(target: ast.expr) -> list[tuple[str, int]]:
    if isinstance(target, ast.Name):
        return [(target.id, target.lineno)]
    if isinstance(target, ast.Tuple | ast.List):
        return [(elt.id, elt.lineno) for elt in target.elts if isinstance(elt, ast.Name)]
    return []
