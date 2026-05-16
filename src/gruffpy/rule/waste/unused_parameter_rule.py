"""Function argument not referenced in the body.

Skip:

- ``self``, ``cls`` (implicit method receivers);
- names starting with ``_`` (convention for "intentionally unused");
- abstract / overload / Protocol stubs;
- methods of classes extending a framework base (signatures must match
  the protocol shape);
- functions carrying framework-hook decorators (the framework calls them
  with conventional args).
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    has_framework_base,
    has_framework_decorator,
    is_abstract_method,
    is_overload_stub,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class UnusedParameterRule(Rule):
    ID = "waste.unused-parameter"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Unused parameter",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
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
            if has_framework_decorator(node):
                continue
            if is_abstract_method(node) or is_overload_stub(node):
                continue
            parents = parent_chain(node)
            parent_cls = next((p for p in reversed(parents) if isinstance(p, ast.ClassDef)), None)
            if parent_cls is not None and (
                has_framework_base(parent_cls) or _has_signature_constrained_base(parent_cls)
            ):
                continue

            referenced = _collect_referenced_names(node.body)
            unused = _unused_params(node, referenced)
            for arg_name, arg_lineno in unused:
                symbol = qualified_symbol(node, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(f"Parameter {arg_name!r} in {symbol!r} is never referenced."),
                        file_path=unit.file.display_path,
                        line=arg_lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            f"Remove the parameter or rename it to ``_{arg_name}`` "
                            "to signal it is intentionally unused."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"parameter": arg_name},
                    ),
                )
        return findings


def _collect_referenced_names(body: list[ast.stmt]) -> set[str]:
    """Return the set of Name occurrences anywhere in *body*.

    Nested scopes are included so closure captures count as legitimate
    references to the outer function's parameters.
    """
    names: set[str] = set()
    for stmt in body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name):
                names.add(sub.id)
    return names


def _unused_params(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, referenced: set[str]
) -> list[tuple[str, int]]:
    args = fn.args
    unused: list[tuple[str, int]] = []
    candidates = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    # Skip self / cls when present as the first positional-only-or-args entry.
    skip_first = bool(args.posonlyargs or args.args)
    leading = (args.posonlyargs + args.args) if skip_first else []
    first_name = leading[0].arg if leading else None
    for arg in candidates:
        if first_name == arg.arg and arg.arg in {"self", "cls"}:
            continue
        if arg.arg.startswith("_"):
            continue
        if arg.arg in referenced:
            continue
        unused.append((arg.arg, arg.lineno))
    return unused


def _has_signature_constrained_base(cls: ast.ClassDef) -> bool:
    return bool(_base_names(cls) & {"Rule", "SourceTextRule", "BaseHTTPRequestHandler"})


def _base_names(cls: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for base in cls.bases:
        name = _name_for(base)
        if name:
            names.add(name)
            names.add(name.split(".")[-1])
    return names


def _name_for(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name_for(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        return _name_for(node.value)
    if isinstance(node, ast.Call):
        return _name_for(node.func)
    return ""
