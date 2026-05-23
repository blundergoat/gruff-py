"""``security.flask-debug-enabled`` - Werkzeug debugger left enabled.

Three shapes, gated to files that import Flask:

- ``app.run(debug=True)``
- ``app.config['DEBUG'] = True``
- ``app.config.update(DEBUG=True)``

The Werkzeug interactive debugger exposes a PIN-protected console that
permits arbitrary Python execution. Enabling it in production code is an
RCE, not just a misconfiguration.
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
from gruffpy.rule.security._security_metadata import finding_security_metadata
from gruffpy.rule.security._security_node_helper import call_keyword, frameworks_in_use

_FRAMEWORK_GATE: frozenset[str] = frozenset({"flask"})
_SOURCE_NEEDLES: tuple[str, ...] = ("debug", "DEBUG")
_REMEDIATION = (
    "Run Flask via a production WSGI server (gunicorn, uWSGI, mod_wsgi) "
    "with debug disabled. The Werkzeug interactive debugger exposes a "
    "PIN-protected console that allows arbitrary Python execution - never "
    "enable it in code that may run in production."
)


class FlaskDebugEnabledRule(Rule):
    """Detect Flask debug mode enabled via ``run(debug=True)`` or config shapes."""

    ID = "security.flask-debug-enabled"

    def definition(self) -> RuleDefinition:
        """Describe the Flask-debug-enabled rule as a high-confidence ERROR.

        ERROR severity because the Werkzeug debugger is an RCE vector in
        production; high confidence because the three matched shapes
        (``run(debug=True)``, ``config['DEBUG'] = True``,
        ``config.update(DEBUG=True)``) are explicit literal-true settings
        with no ambiguous interpretation.

        Returns:
            Definition for the Flask-debug-enabled rule under the security
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Flask debug enabled",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag literal-true debug enables in Flask-context files.

        File-level framework gate: the rule only fires when the unit
        imports Flask (mirrors ``security.header-injection``'s approach).
        Non-literal values (``debug=is_dev``) are intentionally skipped -
        only literal ``True`` triggers, to keep false-positive rate low.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per literal-true debug-enabling shape.
        """
        if unit.tree is None:
            return []
        if not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        if not (frameworks_in_use(unit.tree) & _FRAMEWORK_GATE):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            label = _flask_debug_label(node)
            if label is not None:
                findings.append(_build_finding(definition, unit, node, label))
        return findings


def _flask_debug_label(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return _call_debug_label(node)
    if isinstance(node, ast.Assign):
        return _assign_debug_label(node)
    return None


def _call_debug_label(call: ast.Call) -> str | None:
    if not isinstance(call.func, ast.Attribute):
        return None
    attr = call.func.attr
    if attr == "run":
        debug_kw = call_keyword(call, "debug")
        if debug_kw is not None and _is_true_literal(debug_kw):
            return ".run(debug=True)"
        return None
    if attr == "update" and _receiver_attr(call.func) == "config":
        debug_kw = call_keyword(call, "DEBUG")
        if debug_kw is not None and _is_true_literal(debug_kw):
            return ".config.update(DEBUG=True)"
    return None


def _assign_debug_label(assign: ast.Assign) -> str | None:
    if not _is_true_literal(assign.value):
        return None
    for target in assign.targets:
        if _is_config_debug_subscript(target):
            return ".config['DEBUG'] = True"
    return None


def _is_config_debug_subscript(target: ast.expr) -> bool:
    if not isinstance(target, ast.Subscript):
        return False
    if not (isinstance(target.value, ast.Attribute) and target.value.attr == "config"):
        return False
    key = target.slice
    return isinstance(key, ast.Constant) and key.value == "DEBUG"


def _receiver_attr(func: ast.Attribute) -> str | None:
    if isinstance(func.value, ast.Attribute):
        return func.value.attr
    return None


def _is_true_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    label: str,
) -> Finding:
    line = getattr(node, "lineno", 1)
    end_line = getattr(node, "end_lineno", None)
    return Finding(
        rule_id=definition.id,
        message=f"Flask debug mode enabled via `{label}` - exposes the Werkzeug debugger.",
        file_path=unit.file.display_path,
        line=line,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=end_line,
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "shape": label,
            **finding_security_metadata(
                definition.id,
                source_label="flask-config",
                sink_label="werkzeug-debugger",
            ),
        },
    )
