"""``docs.missing-class-docstring`` - ``class Foo`` without a docstring.

Exempts Protocols, ABCs, TypedDicts, NamedTuples, Enum-like bases, classes
nested inside functions or methods in recognized test files, and
``@dataclass``-decorated classes only when ``class_dataclass_exempt`` is set
in the rule's options (default false). Public dataclasses carry project-facing
schema and invariants, so open-source consumers still need class-level context.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import has_dataclass_decorator, has_framework_base
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._docstring_parser import extract_docstring
from gruffpy.rule.docs._helpers import is_dunder, is_test_file
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class MissingClassDocstringRule(Rule):
    """Detect public classes that lack explanatory class-level documentation."""

    ID = "docs.missing-class-docstring"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the missing class docstring rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Missing class docstring",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_options={"class_dataclass_exempt": False},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for undocumented class declarations.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context with rule options.

        Returns:
            Findings for classes that need docstrings; empty when the tree is absent or no class qualifies.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        dataclass_exempt = settings.options.get(
            "class_dataclass_exempt",
            definition.default_options["class_dataclass_exempt"],
        )

        findings: list[Finding] = []
        for node in _undocumented_classes(
            unit.tree,
            dataclass_exempt=bool(dataclass_exempt),
            display_path=unit.file.display_path,
        ):
            findings.append(_missing_class_docstring_finding(unit, definition, node))
        return findings


def _undocumented_classes(
    tree: ast.AST,
    *,
    dataclass_exempt: bool,
    display_path: str,
) -> list[ast.ClassDef]:
    """Collect every reportable undocumented class definition in the tree.

    Args:
        tree: Parsed module AST, walked with ast.walk so nested classes are inspected.
        dataclass_exempt: When true, classes carrying a dataclass or attrs-style decorator matched by has_dataclass_decorator are skipped; analyse
            passes the class_dataclass_exempt option here.
        display_path: Display path used to skip inline stub classes nested inside functions or methods in recognized test files.

    Returns:
        Reportable class nodes in ast.walk breadth-first order; an empty list when no class qualifies.
    """
    is_test_module = is_test_file(display_path)
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and _should_report_missing_class_docstring(
            node,
            dataclass_exempt=dataclass_exempt,
            is_test_module=is_test_module,
        )
    ]


def _should_report_missing_class_docstring(
    node: ast.ClassDef,
    *,
    dataclass_exempt: bool,
    is_test_module: bool,
) -> bool:
    """Decide whether one class lacks a docstring and falls outside every exemption the rule applies.

    A class is skipped when is_dunder matches its name, when extract_docstring finds any docstring (an empty string still counts as present), when
    has_framework_base matches one of its bases, or when it is defined inside a function or method in a recognized test file. The dataclass check from
    has_dataclass_decorator applies only when dataclass_exempt is true.

    Args:
        node: Class definition to test.
        dataclass_exempt: When true, a class carrying a dataclass or attrs-style decorator matched by has_dataclass_decorator is not reported; when
            false, such classes are judged like any other class.
        is_test_module: Whether the analysed file is a recognized test path.

    Returns:
        True when the class has no docstring and none of the skips above applies, so it should receive a missing class docstring finding; False
        otherwise.
    """
    if is_dunder(node.name):
        return False
    if extract_docstring(node) is not None:
        return False
    if has_framework_base(node):
        return False
    if is_test_module and _is_nested_in_function(node):
        return False
    return not (dataclass_exempt and has_dataclass_decorator(node))


def _is_nested_in_function(node: ast.ClassDef) -> bool:
    """Return whether a class definition is nested inside any function or method.

    Args:
        node: Class definition whose attached parent chain is inspected.

    Returns:
        True when an enclosing FunctionDef or AsyncFunctionDef exists in the parent chain; False otherwise.
    """
    return any(isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef) for parent in parent_chain(node))


def _missing_class_docstring_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
) -> Finding:
    """Build the finding for one undocumented class, naming it by its dotted qualified symbol.

    Args:
        unit: Analysed file whose display path becomes the finding's file path.
        definition: Rule metadata supplying the rule id, default severity, pillar, tier, confidence and secondary pillars copied into the finding.
        node: Undocumented class whose parent chain gives the qualified symbol and whose lineno and end_lineno give the finding's line span.

    Returns:
        Finding whose symbol field holds the qualified symbol, whose message asks for a brief intent description in the class docstring, and whose
        remediation asks for the class's role and any non-obvious invariants, describing behaviour rather than field types; metadata is empty.
    """
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=f"Class {symbol!r} needs a brief intent description in its docstring.",
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=("Describe the class's role and any non-obvious invariants. Describe behaviour, not the field types."),
        secondary_pillars=definition.secondary_pillars,
        metadata={},
    )
