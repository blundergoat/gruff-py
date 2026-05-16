"""Single-class module whose class name doesn't match the snake_cased filename.

Single-class module = exactly one top-level non-private class symbol; adjacent
``_helpers``-style private symbols are ignored. The expected filename is the
snake_case form of the class name.

Examples:

- ``class UserService:`` in ``users.py`` -> expected ``user_service.py``.
- ``class HTTPServer:`` in ``server.py`` -> expected ``http_server.py``.

Skip ``__init__.py`` (intentionally re-exports many classes).
"""

import ast
import re
from pathlib import Path

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule


class ModuleNameMismatchRule(Rule):
    ID = "naming.module-name-mismatch"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Module name mismatch",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if not isinstance(unit.tree, ast.Module):
            return []
        filename = Path(unit.file.display_path).name
        if filename == "__init__.py" or not filename.endswith(".py"):
            return []
        stem = filename[:-3]

        public_classes = [
            node
            for node in unit.tree.body
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_")
        ]
        if len(public_classes) != 1:
            return []
        cls = public_classes[0]
        expected_stem = _camel_to_snake(cls.name)
        if expected_stem == stem:
            return []

        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"Single-class module {filename!r} should be named "
                    f"``{expected_stem}.py`` to match the class {cls.name!r}."
                ),
                file_path=unit.file.display_path,
                line=cls.lineno,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=cls.end_lineno,
                symbol=cls.name,
                remediation=f"Rename {filename!r} to ``{expected_stem}.py``.",
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "expectedFilename": f"{expected_stem}.py",
                    "actualFilename": filename,
                    "class": cls.name,
                },
            )
        ]


def _camel_to_snake(name: str) -> str:
    out = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    out = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", out)
    return out.lower()
