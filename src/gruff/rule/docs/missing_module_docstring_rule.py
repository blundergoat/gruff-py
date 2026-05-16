"""``docs.missing-module-docstring`` — module without a top-of-file docstring.

Skips empty modules and ``__init__.py`` files that contain only imports
and ``__all__`` declarations (re-export shims).
"""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.docs._docstring_parser import extract_docstring
from gruff.rule.docs._helpers import is_test_file
from gruff.rule.rule import Rule


class MissingModuleDocstringRule(Rule):
    ID = "docs.missing-module-docstring"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Missing module docstring",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
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
                message="Module has no top-of-file docstring.",
                file_path=unit.file.display_path,
                line=1,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    "Add a one-paragraph docstring at the top of the module describing its purpose."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={},
            ),
        ]


def _is_reexport_shim(module: ast.Module, display_path: str) -> bool:
    """True if *module* looks like an ``__init__.py`` re-export shim.

    A shim contains only imports and at most a single ``__all__`` assignment.
    Anything else (classes, functions, executable code) disqualifies it.
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
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "__all__"
        ):
            continue
        return False
    return True
