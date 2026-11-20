"""``docs.missing-module-docstring`` - module without a top-of-file docstring.

Skips empty modules and ``__init__.py`` files that contain only imports
and ``__all__`` declarations (re-export shims).
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
from gruffpy.rule.docs._docstring_parser import extract_docstring
from gruffpy.rule.docs._helpers import is_test_file
from gruffpy.rule.rule import Rule


class MissingModuleDocstringRule(Rule):
    """Detect source modules that lack top-of-file documentation."""

    ID = "docs.missing-module-docstring"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the missing module docstring rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Missing module docstring",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for a missing module docstring.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer.

        Returns:
            One finding for a nonempty undocumented module outside tests and re-export shims; empty for other inputs.
        """
        if not isinstance(unit.tree, ast.Module):
            return []
        if not unit.tree.body:
            return []
        if is_test_file(unit.file.display_path):
            return []
        if extract_docstring(unit.tree) is not None:
            return []
        if _is_reexport_shim(unit.tree, unit.file.display_path):
            return []

        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message="Module needs a top-of-file docstring describing its purpose.",
                file_path=unit.file.display_path,
                line=1,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=("Name what this module owns and what callers can rely on, in one short paragraph at the top of the file."),
                secondary_pillars=definition.secondary_pillars,
                metadata={},
            ),
        ]


def _is_reexport_shim(module: ast.Module, display_path: str) -> bool:
    """Decide whether an __init__.py module contains only imports and supported __all__ assignments.

    Single-target and annotated assignments to __all__ qualify; any other top-level statement disqualifies the module.

    Args:
        module: Parsed module whose top-level statements are checked one by one.
        display_path: Display path of the file; only the __init__.py suffix is checked.

    Returns:
        True when the path has the __init__.py suffix and every top-level statement qualifies, including an empty module; False otherwise.
    """
    if not display_path.endswith("__init__.py"):
        return False
    for node in module.body:
        if isinstance(node, ast.Import | ast.ImportFrom):
            continue
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id == "__all__":
                continue
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "__all__":
            continue
        return False
    return True
