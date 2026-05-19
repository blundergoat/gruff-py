"""Type-prefixed Hungarian-notation identifiers.

Detects names whose first underscore-token is a type-prefix:
``i_count``, ``s_name``, ``b_is_valid``, ``arr_items``, ``dict_users``,
``str_message``, ``int_total``, ``f_ratio``, etc. Python conventions
explicitly reject this — PEP 8, mypy, type hints make the type self-evident.

Scope: function/method names, parameter names, local variable assignments,
class-body attribute assignments. Class names are NOT scanned (a class
``StrSerializer`` is fine — ``Str`` is the domain, not a type prefix).
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
from gruffpy.rule.rule import Rule

# Type-prefix tokens that signal Hungarian notation when they're the
# FIRST snake-case segment of an identifier. Kept narrow on purpose;
# false positives on real domain names (e.g. ``int_id`` meaning integer ID)
# erode trust faster than missed detections.
_HUNGARIAN_PREFIXES: frozenset[str] = frozenset(
    {
        "i",
        "s",
        "b",
        "f",
        "d",
        "n",
        "p",
        "lp",
        "sz",
        "ch",
        "int",
        "str",
        "bool",
        "flt",
        "dbl",
        "num",
        "arr",
        "lst",
        "dict",
        "tup",
        "obj",
        "ptr",
    }
)


class HungarianNotationRule(Rule):
    """Detect identifiers whose first token is a type-prefix like `i_count` or `arr_items`."""

    ID = "naming.hungarian-notation"

    def definition(self) -> RuleDefinition:
        """Describe the Hungarian-notation rule as a high-confidence warning.

        High confidence because the prefix set is intentionally narrow —
        false positives on real domain names (``int_id``) erode trust faster
        than missed detections.

        Returns:
            Definition for the Hungarian-notation rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Hungarian notation",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag function/parameter/variable names whose first snake-case token is a type prefix.

        Class names are intentionally not scanned (``StrSerializer`` is a
        domain name, not a Hungarian prefix). The check requires an
        underscore in the name so single-token identifiers like ``str`` or
        ``int`` are not flagged.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per unique ``(name, line)`` identifier with a
            Hungarian prefix.
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
                if not _has_hungarian_prefix(name):
                    continue
                seen.add((name, lineno))
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Identifier {name!r} uses Hungarian-notation type prefix; "
                            "rely on type hints / annotations instead."
                        ),
                        file_path=unit.file.display_path,
                        line=lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=lineno,
                        symbol=name,
                        remediation=(
                            "Rename to drop the type prefix "
                            f"(e.g. ``{name}`` → ``{_drop_prefix(name)}``)."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"identifier": name, "prefix": _prefix_of(name)},
                    ),
                )
        return findings


def _identifiers_in(node: ast.AST) -> list[tuple[str, int]]:
    """Return ``(name, lineno)`` pairs for identifiers *node* introduces."""
    handler = _IDENTIFIER_HANDLERS.get(type(node))
    return handler(node) if handler is not None else []


def _function_identifiers(node: ast.AST) -> list[tuple[str, int]]:
    assert isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    result: list[tuple[str, int]] = [(node.name, node.lineno)]
    all_args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
    result.extend((arg.arg, arg.lineno) for arg in all_args)
    if node.args.vararg is not None:
        result.append((node.args.vararg.arg, node.args.vararg.lineno))
    if node.args.kwarg is not None:
        result.append((node.args.kwarg.arg, node.args.kwarg.lineno))
    return result


def _assign_identifiers(node: ast.AST) -> list[tuple[str, int]]:
    assert isinstance(node, ast.Assign)
    out: list[tuple[str, int]] = []
    for target in node.targets:
        out.extend(_target_identifiers(target))
    return out


def _annassign_identifiers(node: ast.AST) -> list[tuple[str, int]]:
    assert isinstance(node, ast.AnnAssign)
    return _target_identifiers(node.target)


def _target_identifiers(node: ast.AST) -> list[tuple[str, int]]:
    if isinstance(node, ast.Name):
        return [(node.id, node.lineno)]
    if isinstance(node, ast.Tuple | ast.List):
        return [(elt.id, elt.lineno) for elt in node.elts if isinstance(elt, ast.Name)]
    return []


_IDENTIFIER_HANDLERS = {
    ast.FunctionDef: _function_identifiers,
    ast.AsyncFunctionDef: _function_identifiers,
    ast.Assign: _assign_identifiers,
    ast.AnnAssign: _annassign_identifiers,
}


def _has_hungarian_prefix(name: str) -> bool:
    if name.startswith("__") and name.endswith("__"):
        return False  # dunder
    stripped = name.lstrip("_")
    if "_" not in stripped:
        return False
    prefix = stripped.split("_", 1)[0]
    return prefix.lower() in _HUNGARIAN_PREFIXES


def _prefix_of(name: str) -> str:
    return name.lstrip("_").split("_", 1)[0]


def _drop_prefix(name: str) -> str:
    leading = name[: len(name) - len(name.lstrip("_"))]
    stripped = name.lstrip("_")
    return leading + stripped.split("_", 1)[1]
