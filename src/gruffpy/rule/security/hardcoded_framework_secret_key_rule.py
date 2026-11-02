"""``security.hardcoded-framework-secret-key`` - Flask/Django SECRET_KEY = '<literal>'.

A module-scope assignment of the form ``SECRET_KEY = "..."`` in a file that
imports Flask or Django is the canonical anti-pattern: the secret is now
in version control, in every developer's checkout, and unrotatable across
environments.

The rule fires on the *shape* (``SECRET_KEY = "..."``) regardless of how
innocuous the literal looks. A development placeholder like ``SECRET_KEY = "dev-key"`` is also
worth flagging because it tends to slip into production.

Only module-scope assignments fire; ``SECRET_KEY`` used as a local
variable inside a function is not the framework setting and is skipped.
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
from gruffpy.rule.security._security_node_helper import frameworks_in_use

_FRAMEWORK_GATE: frozenset[str] = frozenset({"flask", "django"})
_SECRET_KEY_NAME: str = "SECRET_KEY"
_SOURCE_NEEDLES: tuple[str, ...] = ("SECRET_KEY",)
_REMEDIATION = (
    "Read the secret from an environment variable or secret manager: "
    "`SECRET_KEY = os.environ['SECRET_KEY']`. A committed literal can't be "
    "rotated without a code change and is visible to anyone with repo access."
)


class HardcodedFrameworkSecretKeyRule(Rule):
    """Detect module-scope ``SECRET_KEY = '<literal>'`` in Flask/Django files."""

    ID = "security.hardcoded-framework-secret-key"

    def definition(self) -> RuleDefinition:
        """Describe the hardcoded-SECRET_KEY rule as a high-confidence ERROR.

        ERROR severity because a leaked SECRET_KEY in Flask/Django defeats
        session signing, password reset tokens, and CSRF protection; high
        confidence because the matched shape (module-scope assignment with
        a string literal value) is unambiguous.

        Returns:
            Definition for the hardcoded-SECRET_KEY rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Hardcoded framework SECRET_KEY",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag module-scope ``SECRET_KEY = "..."`` in Flask/Django files.

        Walks only the module body - assignments inside functions, classes,
        or branches are skipped. The framework gate (Flask or Django
        imported) keeps the rule from firing on unrelated modules that
        happen to have a constant named ``SECRET_KEY``.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per module-scope SECRET_KEY assignment with a
            string-literal value.
        """
        if unit.tree is None or _SECRET_KEY_NAME not in unit.source:
            return []
        if not isinstance(unit.tree, ast.Module):
            return []
        if not (frameworks_in_use(unit.tree) & _FRAMEWORK_GATE):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for stmt in unit.tree.body:
            for assign in _iter_secret_key_assignments(stmt):
                findings.append(_build_finding(definition, unit, assign))
        return findings


def _iter_secret_key_assignments(stmt: ast.stmt) -> list[ast.stmt]:
    """Select a direct secret-key assignment with a string-literal value.

    This helper does not recurse into scopes or branches, and does not inspect the string's content.

    Args:
        stmt: Direct module-body statement supplied after the caller's framework gate.

    Returns:
        A single-item list containing a matching assignment or annotated assignment; empty otherwise.
    """
    if isinstance(stmt, ast.Assign):
        if not _is_string_literal_value(stmt.value):
            return []
        if any(_is_secret_key_target(target) for target in stmt.targets):
            return [stmt]
        return []
    if isinstance(stmt, ast.AnnAssign):
        if stmt.value is None or not _is_string_literal_value(stmt.value):
            return []
        if _is_secret_key_target(stmt.target):
            return [stmt]
    return []


def _is_secret_key_target(target: ast.expr) -> bool:
    """Recognize the bare framework secret-key setting name.

    Args:
        target: Assignment target to compare with the setting name.

    Returns:
        True for a plain name equal to SECRET_KEY; false for attributes or other targets.
    """
    return isinstance(target, ast.Name) and target.id == _SECRET_KEY_NAME


def _is_string_literal_value(value: ast.expr) -> bool:
    """Recognize a plain string constant assigned to a framework setting.

    Args:
        value: Assigned expression to inspect without interpreting its string content.

    Returns:
        True for string constants, including empty strings; false for other expressions.
    """
    return isinstance(value, ast.Constant) and isinstance(value.value, str)


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    assign: ast.stmt,
) -> Finding:
    """Build the finding for a matched framework secret-key assignment.

    Args:
        definition: Rule identity, severity, and classification to copy into the finding.
        unit: Analysis unit providing the displayed file path.
        assign: Matched assignment supplying the finding's source span.

    Returns:
        Finding with the setting name and security classification, without copying the assigned value.
    """
    return Finding(
        rule_id=definition.id,
        message=("Module-scope `SECRET_KEY` is assigned a string literal - read it from the environment instead."),
        file_path=unit.file.display_path,
        line=assign.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=assign.end_lineno,
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "name": _SECRET_KEY_NAME,
            **finding_security_metadata(
                definition.id,
                source_label="framework-config",
                sink_label="signing-key",
            ),
        },
    )
