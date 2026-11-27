"""Flag classes missing a class-level docstring during `gruff-py analyse` and `hook` runs.

Use this rule so reviewers scanning a repository or pull request can see each class's purpose and invariants without reading every method.
Structural framework bases and function-local test stubs stay quiet by default, while dataclasses stay flagged unless opted out.

- Always exempt: dunder-named classes, Protocol/ABC/TypedDict/NamedTuple/Enum bases, and classes nested inside functions in test files.
- Configurable exemption: set `class_dataclass_exempt: true` to skip `@dataclass` and attrs-style classes when field types are self-explanatory.
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
    """Detect classes that lack a class-level docstring explaining their role and invariants.

    The analyser runs this rule on every parsed Python file so developers see undocumented domain types in terminal, JSON, and SARIF output.
    Configure `class_dataclass_exempt` in `.gruff-py.yaml` or `pyproject.toml` if your team treats dataclass fields as sufficient documentation.
    """

    ID = "docs.missing-class-docstring"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry, `list-rules`, and report formatters.

        Returns:
            Definition for the missing class docstring rule, including the default `class_dataclass_exempt` option.
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
        """Inspect one parsed Python file for class definitions that still need a docstring.

        Called by the analysis runner during `analyse`, `summary`, `report`, and `hook` runs after parsing produces an AST.

        Args:
            unit: Parsed source file to inspect; `unit.tree` is None for non-Python files, syntax errors, or deep-scan budget skips.
            context: Rule execution context supplying user config options such as `class_dataclass_exempt`.

        Returns:
            Findings for classes that need docstrings; an empty list when the file has no AST or every class is documented or exempt.
        """
        # Non-Python files, syntax errors, and budget-skipped files have no AST, so this AST rule stays silent.
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        dataclass_exempt = settings.options.get(
            "class_dataclass_exempt",
            definition.default_options["class_dataclass_exempt"],
        )

        findings: list[Finding] = []
        # Emit one finding per undocumented non-exempt class so each appears at its class header line in the CLI report.
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
    """Walk the module AST and collect every class definition that should receive a missing-docstring finding.

    Args:
        tree: Parsed module AST, walked with ast.walk so nested helper classes are checked alongside top-level classes.
        dataclass_exempt: When true, classes carrying a dataclass or attrs-style decorator are skipped per user configuration.
        display_path: Relative source path used to exempt inline stub classes defined inside test functions or test methods.

    Returns:
        Reportable class nodes in breadth-first walk order; an empty list when every class is documented or exempt.
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
    """Check whether one class lacks a docstring and falls outside every exemption the rule honours.

    Keeps low-signal test stubs and structural framework types out of the developer's warning list while still flagging domain classes.

    Args:
        node: Class definition currently being evaluated.
        dataclass_exempt: When true, `@dataclass` and attrs-style classes are skipped; when false, they require a docstring like other classes.
        is_test_module: Whether the analysed file sits under a recognized test path.

    Returns:
        True when the class should produce a finding for the user; False when a docstring exists or an exemption applies.
    """
    # Internal dunder class names are skipped because they are synthetic or language-level definitions.
    if is_dunder(node.name):
        return False
    # Any docstring (even an empty literal) means the class is handled by content-quality rules rather than missing-docstring.
    if extract_docstring(node) is not None:
        return False
    # Protocols, ABCs, TypedDicts, NamedTuples, and Enums are structural declarations that rarely need separate prose.
    if has_framework_base(node):
        return False
    # For example, a developer defines `class FakeClient:` inside `def test_retry():`; inline test stubs stay quiet.
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
