"""``security.jinja2-autoescape-off`` — Jinja2 Environment without autoescape.

Jinja2's ``Environment`` constructor defaults ``autoescape`` to ``False``
(unlike Flask's preconfigured environment). Templates rendered through such
an environment do not escape HTML / JS / URL contexts, exposing the
application to stored and reflected XSS.

The rule fires on ``jinja2.Environment(...)`` (and the standard import-alias
forms) when ``autoescape`` is absent or explicitly ``False``. ``autoescape=True``
or ``autoescape=select_autoescape(...)`` is treated as safe. Other dynamic
expressions for ``autoescape`` are skipped (conservative — we cannot prove
unsafety).

Gated to files that import ``jinja2`` to avoid false positives on unrelated
classes also named ``Environment``.
"""

import ast
from dataclasses import dataclass

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

_REMEDIATION = (
    "Pass `autoescape=True`, or `autoescape=jinja2.select_autoescape(['html', "
    "'xml'])` if you need per-extension control. Jinja2's default is "
    "`autoescape=False`, which leaves templates exposed to XSS unless the "
    "host framework (e.g. Flask) wraps the environment."
)


class Jinja2AutoescapeOffRule(Rule):
    """Detect ``jinja2.Environment(...)`` constructed without ``autoescape=True``."""

    ID = "security.jinja2-autoescape-off"

    def definition(self) -> RuleDefinition:
        """Describe the jinja2-autoescape-off rule as a high-confidence ERROR.

        ERROR severity because the missing autoescape silently disables XSS
        protection across every template rendered through the environment;
        high confidence because the matched constructor shape and kwarg
        check are unambiguous.

        Returns:
            Definition for the jinja2-autoescape-off rule under the security
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Jinja2 autoescape disabled",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``jinja2.Environment(...)`` without ``autoescape=True``.

        Resolves the common alias shapes (``import jinja2``, ``from jinja2
        import Environment``, ``from jinja2 import Environment as Env``)
        before testing the call target. Skips constructors whose
        ``autoescape`` argument is literal ``True`` or a call to
        ``select_autoescape``.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per Environment construction without autoescape.
        """
        if unit.tree is None or "jinja2" not in unit.source:
            return []
        definition = self.definition()
        aliases = _Jinja2Aliases.from_tree(unit.tree)
        if not aliases.environment_names:
            return []
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            target = call_target_name(node)
            if target not in aliases.environment_names:
                continue
            if _is_autoescape_safe(node):
                continue
            findings.append(_build_finding(definition, unit, node))
        return findings


@dataclass(frozen=True, slots=True)
class _Jinja2Aliases:
    """Tracks call-target names that resolve to ``jinja2.Environment``."""

    environment_names: frozenset[str]

    @classmethod
    def from_tree(cls, tree: ast.AST) -> "_Jinja2Aliases":
        """Collect the local names bound to ``jinja2.Environment``.

        Args:
            tree: Module AST to inspect for jinja2 imports.

        Returns:
            Aliases record listing every call-target name that resolves to
            ``jinja2.Environment`` in this module.
        """
        names: set[str] = set()
        if not isinstance(tree, ast.Module):
            return cls(frozenset())
        for node in tree.body:
            if isinstance(node, ast.Import):
                names.update(_environment_names_from_import(node))
            elif isinstance(node, ast.ImportFrom):
                names.update(_environment_names_from_from_import(node))
        return cls(frozenset(names))


def _environment_names_from_import(node: ast.Import) -> set[str]:
    names: set[str] = set()
    for alias in node.names:
        if alias.name != "jinja2":
            continue
        head = alias.asname or "jinja2"
        names.add(f"{head}.Environment")
    return names


def _environment_names_from_from_import(node: ast.ImportFrom) -> set[str]:
    if node.module != "jinja2":
        return set()
    names: set[str] = set()
    for alias in node.names:
        if alias.name == "Environment":
            names.add(alias.asname or "Environment")
    return names


def _is_autoescape_safe(call: ast.Call) -> bool:
    value = call_keyword(call, "autoescape")
    if value is None:
        return False
    return not (isinstance(value, ast.Constant) and value.value is False)


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            "Jinja2 `Environment(...)` without `autoescape=True` leaves "
            "rendered templates exposed to XSS."
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
            "target": "jinja2.Environment",
            **finding_security_metadata(
                definition.id,
                source_label="template-context",
                sink_label="html-output",
            ),
        },
    )
