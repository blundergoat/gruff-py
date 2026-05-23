"""``security.cors-wildcard-with-credentials`` - CORS wildcard origin + credentials.

The combination of ``Access-Control-Allow-Origin: *`` and
``Access-Control-Allow-Credentials: true`` is forbidden by the CORS spec
and ignored by browsers - but more importantly, code that *tries* to set
both is almost always misconfigured: the developer wanted credentialed
requests from a specific origin and reached for ``*`` by mistake. When
a server *can* return credentials to any origin (some implementations
permit this combination), any malicious site can issue authenticated
requests on behalf of the user's browser session.

Match shapes:

- ``CORS(app, supports_credentials=True, origins="*")`` (Flask-CORS)
- ``CORS(app, supports_credentials=True, origins=["*"])`` (Flask-CORS)
- ``CORS(app, supports_credentials=True)`` with no ``origins`` (defaults
  to wildcard in Flask-CORS)

The raw header-assignment shape
(``response.headers["Access-Control-Allow-Origin"] = "*"`` co-located with
``Allow-Credentials: true``) is out of scope for v1 - it requires
intra-function correlation; the Flask-CORS API covers the common case.
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
from gruffpy.rule.security._security_node_helper import call_keyword, call_target_name

_SOURCE_NEEDLES: tuple[str, ...] = ("CORS", "supports_credentials")
_REMEDIATION = (
    "Either set `supports_credentials=False`, or replace `origins='*'` with "
    "an explicit allow-list (`origins=['https://app.example.com']`). The "
    "wildcard-plus-credentials combination is rejected by browsers and "
    "indicates a misconfigured cross-origin policy."
)


class CorsWildcardWithCredentialsRule(Rule):
    """Detect Flask-CORS calls that combine wildcard origins with credentials."""

    ID = "security.cors-wildcard-with-credentials"

    def definition(self) -> RuleDefinition:
        """Describe the CORS-wildcard-with-credentials rule as a high-confidence ERROR.

        ERROR severity because the combination is rejected by browsers (so
        the developer's intent doesn't work) and indicates a misconfigured
        CORS policy; high confidence because the kwarg combination is
        explicit and unambiguous.

        Returns:
            Definition for the CORS-wildcard-with-credentials rule under
            the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="CORS wildcard origin with credentials",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``CORS(..., supports_credentials=True, origins='*')`` shapes.

        Matches calls whose target leaf is ``CORS`` and which combine a
        truthy ``supports_credentials`` literal with either an explicit
        wildcard ``origins`` value or a missing ``origins`` kwarg
        (Flask-CORS defaults to wildcard).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unsafe CORS configuration call.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            if not _is_cors_call(node):
                continue
            if not _is_credentials_true(call_keyword(node, "supports_credentials")):
                continue
            if not _is_wildcard_origins(call_keyword(node, "origins")):
                continue
            findings.append(_build_finding(definition, unit, node))
        return findings


def _is_cors_call(call: ast.Call) -> bool:
    target = call_target_name(call)
    if target is None:
        return False
    return target.split(".")[-1] == "CORS"


def _is_credentials_true(value: ast.expr | None) -> bool:
    return isinstance(value, ast.Constant) and value.value is True


def _is_wildcard_origins(value: ast.expr | None) -> bool:
    if value is None:
        return True
    if isinstance(value, ast.Constant) and value.value == "*":
        return True
    if isinstance(value, ast.List | ast.Tuple):
        return any(isinstance(item, ast.Constant) and item.value == "*" for item in value.elts)
    return False


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            "CORS configured with `supports_credentials=True` and a wildcard "
            "origin - browsers reject this combination and it signals a "
            "misconfigured cross-origin policy."
        ),
        file_path=unit.file.display_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "shape": "flask-cors",
            **finding_security_metadata(
                definition.id,
                source_label="cross-origin-request",
                sink_label="cors-policy",
            ),
        },
    )
