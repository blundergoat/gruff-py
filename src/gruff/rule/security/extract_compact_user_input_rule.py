"""``security.extract-compact-user-input`` — splat-unpacking of request data into kwargs.

Python equivalent of PHP's ``extract()`` / ``compact()`` smell. Catches:

- ``func(**request.json)``
- ``func(**request.form)``
- ``func(**request.args)`` (Flask)
- ``func(**request.GET)`` / ``request.POST`` / ``request.data`` (Django)
- ``func(**request.query_params)`` (FastAPI)

The risk is the same as ``extract`` in PHP: arbitrary user-controlled keys
become argument names in the receiving function.
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
from gruff.rule.rule import Rule

_REQUEST_ATTRS: frozenset[str] = frozenset(
    {"json", "form", "args", "GET", "POST", "data", "query_params", "values"}
)


class ExtractCompactUserInputRule(Rule):
    ID = "security.extract-compact-user-input"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Splat-unpacked user input",
            pillar=Pillar.SECURITY,
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
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg is not None:
                    continue
                if not _is_request_attr(kw.value):
                    continue
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            "User-controlled dict splatted into a function's keyword "
                            "arguments (`**request.<attr>`)."
                        ),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        remediation=(
                            "Extract explicit fields by name (`request.json['x']`) and "
                            "pass them positionally or via known keyword arguments."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
                break
        return findings


def _is_request_attr(node: ast.expr) -> bool:
    """True when *node* is ``<something>.request.<attr>`` or ``request.<attr>``."""
    if not isinstance(node, ast.Attribute):
        return False
    if node.attr not in _REQUEST_ATTRS:
        return False
    receiver = node.value
    if isinstance(receiver, ast.Name) and receiver.id == "request":
        return True
    return isinstance(receiver, ast.Attribute) and receiver.attr == "request"
