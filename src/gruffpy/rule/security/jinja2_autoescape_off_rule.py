"""``security.jinja2-autoescape-off`` - Jinja2 Environment without autoescape.

Jinja2's ``Environment`` constructor defaults ``autoescape`` to ``False``
(unlike Flask's preconfigured environment). Templates rendered through such
an environment do not escape HTML / JS / URL contexts, exposing the
application to stored and reflected XSS.

The rule fires on ``jinja2.Environment(...)`` (and the standard import-alias
forms) when ``autoescape`` is absent or explicitly ``False``. ``autoescape=True``
or ``autoescape=select_autoescape(...)`` is treated as safe. Other dynamic
expressions for ``autoescape`` are skipped (conservative - we cannot prove
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

        Missing or literal-False autoescape disables automatic escaping; explicit constructor and argument checks support high confidence.

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
        """Flag recognized Jinja2 Environment calls with no explicit autoescape keyword or with that keyword set to literal False.

        Top-level imports supply aliases. Other values supplied through the explicit autoescape keyword are exempt.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per matched constructor, or an empty list when parsing, supported imports or matching calls are absent.
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
        """Collect candidate Environment call spellings from top-level Jinja2 imports.

        Args:
            tree: AST whose top-level imports are inspected when it is a module.

        Returns:
            Aliases record containing candidate Environment call spellings from top-level imports, without rebinding checks;
            empty when the tree is not a module or no supported import occurs.
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
    """Collect Environment call-target spellings from direct jinja2 imports.

    Args:
        node: Import statement whose module names and aliases are inspected.

    Returns:
        Qualified Environment names for exact jinja2 imports, or an empty set if none occur.
    """
    names: set[str] = set()
    for alias in node.names:
        if alias.name != "jinja2":
            continue
        head = alias.asname or "jinja2"
        names.add(f"{head}.Environment")
    return names


def _environment_names_from_from_import(node: ast.ImportFrom) -> set[str]:
    """Collect local Environment names imported from jinja2.

    Args:
        node: From-import statement whose module and imported names are inspected.

    Returns:
        Local names or aliases for Environment, or an empty set for other modules and names.
    """
    if node.module != "jinja2":
        return set()
    names: set[str] = set()
    for alias in node.names:
        if alias.name == "Environment":
            names.add(alias.asname or "Environment")
    return names


def _is_autoescape_safe(call: ast.Call) -> bool:
    """Check whether the autoescape argument exempts a constructor from this rule.

    Args:
        call: Environment constructor call whose named autoescape argument is inspected.

    Returns:
        False when autoescape is absent or literal False; True for every other supplied expression.
    """
    value = call_keyword(call, "autoescape")
    if value is None:
        return False
    return not (isinstance(value, ast.Constant) and value.value is False)


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
) -> Finding:
    """Build the finding for an Environment call that failed the autoescape check.

    Args:
        definition: Rule metadata supplying identity and classification.
        unit: Source unit supplying the displayed file path.
        call: Matched constructor call supplying the source range.

    Returns:
        A finding with the autoescape remediation and template-output metadata.
    """
    return Finding(
        rule_id=definition.id,
        message=("Jinja2 `Environment(...)` without `autoescape=True` leaves rendered templates exposed to XSS."),
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
