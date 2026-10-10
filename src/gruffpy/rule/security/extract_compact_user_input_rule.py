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

        Medium confidence because the rule matches by attribute name alone
        (``request.json``, ``.form``, etc.) without verifying that ``request``
        is actually a web-framework request object; a local variable named
        ``request`` will also trip the rule.

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
        """Flag ``f(**request.<attr>)`` patterns across major web frameworks.

        Splatting user-controlled dicts into kwargs is Python's analogue of
        PHP's ``extract()`` - the attacker chooses the parameter names that
        get bound. Covers Flask/Django/FastAPI access patterns (``.json``,
        ``.form``, ``.args``, ``.GET``/``.POST``/``.data``,
        ``.query_params``, ``.values``).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per call site that splats a request attribute.
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
    """True for ``request.<attr>``, ``self.request.<attr>``, or ``<imported>.request.<attr>``.

    Matches the receiver policy in ``_security_taint_helper`` so the two
    request-detecting rules agree on the shape. An application object's
    ``other.request`` binds a parameter or local, not an imported module.

    Args:
        node: Expression splatted into a callee's keyword arguments.
        imported_modules: Names bound by an import in the same file.

    Returns:
        True for a recognised request receiver; false for application objects.
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
