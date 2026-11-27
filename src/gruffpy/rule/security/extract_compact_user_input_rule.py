"""``security.extract-compact-user-input`` - splat-unpacking of request data into kwargs.

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

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_node_helper import imported_module_names

_REQUEST_ATTRS: frozenset[str] = frozenset({"json", "form", "args", "GET", "POST", "data", "query_params", "values"})


class ExtractCompactUserInputRule(Rule):
    """Detect splat-unpacking of `request.json`/`form`/`args` into a callee's kwargs."""

    ID = "security.extract-compact-user-input"

    def definition(self) -> RuleDefinition:
        """Describe the splat-unpacked-user-input rule as a medium-confidence warning.

        Medium confidence reflects syntax-based request receivers; their runtime types and data origins are not verified.

        Returns:
            Definition for the extract-compact-user-input rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Splat-unpacked user input",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag calls that unpack supported request attributes into keyword arguments.

        Treat request, self.request, and imported-name request receivers as potential user input; receiver types are not verified.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per call site that unpacks a supported request attribute. Empty when syntax is unavailable or no call matches.
        """
        if unit.tree is None or "request" not in unit.source or "**" not in unit.source:
            return []
        definition = self.definition()
        imported_modules = imported_module_names(unit.tree)
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg is not None:
                    continue
                if not _is_request_attribute(kw.value, imported_modules):
                    continue
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=("User-controlled dict splatted into a function's keyword arguments (`**request.<attr>`)."),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        remediation=(
                            "Extract explicit fields by name (`request.json['x']`) and pass them positionally or via known keyword arguments."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
                break
        return findings


def _is_request_attribute(node: ast.expr, imported_modules: frozenset[str]) -> bool:
    """Recognize supported request attributes on request, self.request, or an imported name's request receiver.

    Use the same receiver shapes as _security_taint_helper; imports are checked by bound name, without runtime type or shadowing analysis.

    Args:
        node: Expression splatted into a callee's keyword arguments.
        imported_modules: Names bound by an import in the same file.

    Returns:
        True for a supported attribute and receiver shape; false otherwise.
    """
    if not isinstance(node, ast.Attribute):
        return False
    if node.attr not in _REQUEST_ATTRS:
        return False
    receiver = node.value
    if isinstance(receiver, ast.Name) and receiver.id == "request":
        return True
    if not isinstance(receiver, ast.Attribute) or receiver.attr != "request":
        return False
    if not isinstance(receiver.value, ast.Name):
        return False
    return receiver.value.id == "self" or receiver.value.id in imported_modules
