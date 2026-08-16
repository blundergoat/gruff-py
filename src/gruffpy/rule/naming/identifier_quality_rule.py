"""Guide users away from identifiers that still read like draft placeholders.

The scan matches exact first tokens such as ``temp`` and ``foo``, plus numbered
forms such as ``result1``. Legitimate domain words such as ``todo`` stay outside
the rule because a name alone cannot prove unfinished work.
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
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule

_PLACEHOLDER_TOKENS: frozenset[str] = frozenset(
    {"temp", "foo", "bar", "baz", "qux", "thing", "stuff"}
)
_NUMBERED_BASES: frozenset[str] = frozenset({"result", "data", "value", "item", "var", "x"})


class IdentifierQualityRule(Rule):
    """Report identifiers that obscure the value or role a user will review.

    Normal scans use token boundaries so domain vocabulary remains available.
    Users act on each result by choosing a name that explains the concrete role.
    """

    ID = "naming.identifier-quality"

    def definition(self) -> RuleDefinition:
        """Describe the high-confidence warning shown in rule listings.

        Returns:
            Definition for the identifier-quality rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Identifier quality",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Return draft-placeholder findings visible in the user's scan.

        Args:
            unit: Parsed user file; a missing tree means no identifiers can be reviewed.
            context: Active scan context; empty settings are valid because this rule
                has no user options.

        Returns:
            One finding per name/line; empty means every identifier is descriptive.
        """
        # A parse failure leaves the UI without reliable declaration names.
        if unit.tree is None:
            return []
        definition = self.definition()
        user_findings: list[Finding] = []
        reported_identifiers: set[tuple[str, int]] = set()

        # Each parsed declaration may contribute a renameable user-facing name.
        for candidate_node in ast.walk(unit.tree):
            # One declaration can expose multiple parameter or assignment names.
            for identifier_name, identifier_line in _identifiers_in(candidate_node):
                # Duplicate AST routes must not repeat the same UI result.
                if (identifier_name, identifier_line) in reported_identifiers:
                    continue
                placeholder_reason = _placeholder_pattern(identifier_name)
                # No reason means the identifier already communicates a useful role.
                if placeholder_reason is None:
                    continue
                reported_identifiers.add((identifier_name, identifier_line))
                user_findings.append(
                    _finding_for_identifier(
                        definition,
                        unit.file.display_path,
                        identifier_name,
                        identifier_line,
                        placeholder_reason,
                    )
                )
        return user_findings


def _finding_for_identifier(
    definition: RuleDefinition,
    file_path: str,
    identifier_name: str,
    identifier_line: int,
    placeholder_reason: str,
) -> Finding:
    """Build the warning and rename guidance shown to a scan user.

    Args:
        definition: Stable rule policy used by reporters.
        file_path: User-visible path; empty means the source has no display path.
        identifier_name: Name shown in the result; empty names never reach here.
        identifier_line: One-based source line shown to the user.
        placeholder_reason: Token evidence explaining why the name was flagged.

    Returns:
        Complete finding with unchanged message and identity inputs.
    """
    return Finding(
        rule_id=definition.id,
        message=f"Identifier {identifier_name!r} is a placeholder ({placeholder_reason}).",
        file_path=file_path,
        line=identifier_line,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=identifier_line,
        symbol=identifier_name,
        remediation="Rename to something descriptive of the value or role.",
        secondary_pillars=definition.secondary_pillars,
        metadata={"identifier": identifier_name, "pattern": placeholder_reason},
    )


def _placeholder_pattern(identifier_name: str) -> str | None:
    """Return token evidence when a user's identifier reads like a draft name.

    Args:
        identifier_name: Declaration name; empty text has no placeholder evidence.

    Returns:
        User-facing reason, or ``None`` when the name should stay out of results.
    """
    # Python-owned dunder names keep their language-defined spelling.
    if identifier_name.startswith("__") and identifier_name.endswith("__"):
        return None
    identifier_tokens = lower_tokens(identifier_name)
    # An empty tokenizer result gives the UI no placeholder word to explain.
    if not identifier_tokens:
        return None
    # Exact first tokens cover draft names such as temp/cache-independent temp_item.
    if _has_placeholder_prefix(identifier_tokens):
        return f"placeholder token {identifier_tokens[0]!r}"
    # Numbered families cover user-visible drafts such as result1 and data42.
    if _is_numbered_placeholder(identifier_tokens):
        return f"numbered placeholder {identifier_tokens[0]!r}+{identifier_tokens[1]!r}"
    return None


def _has_placeholder_prefix(identifier_tokens: list[str]) -> bool:
    """Return whether the first user-visible token is reserved for draft names.

    Args:
        identifier_tokens: Nonempty lowercase tokens from one declaration.

    Returns:
        ``True`` when the name begins with a reviewed placeholder token.
    """
    return identifier_tokens[0] in _PLACEHOLDER_TOKENS


def _is_numbered_placeholder(identifier_tokens: list[str]) -> bool:
    """Return whether a user's name starts with a numbered draft family.

    Args:
        identifier_tokens: Lowercase tokens; empty/single-token names return false.

    Returns:
        ``True`` for shapes such as ``result1`` or ``data42``.
    """
    return (
        len(identifier_tokens) >= 2
        and identifier_tokens[0] in _NUMBERED_BASES
        and identifier_tokens[1].isdigit()
    )


def _identifiers_in(candidate_node: ast.AST) -> list[tuple[str, int]]:
    """Return renameable identifiers exposed by one parsed user declaration.

    Args:
        candidate_node: Parsed node; unrelated nodes return an empty list.

    Returns:
        Identifier/line pairs shown in findings, or empty for unsupported nodes.
    """
    # Function names and parameters are both visible in the user's API journey.
    if isinstance(candidate_node, ast.FunctionDef | ast.AsyncFunctionDef):
        return [
            (candidate_node.name, candidate_node.lineno),
            *_argument_identifiers(candidate_node.args),
        ]
    # Class declarations expose one renameable type name.
    if isinstance(candidate_node, ast.ClassDef):
        return [(candidate_node.name, candidate_node.lineno)]
    # Chained and unpacked assignments may expose several user names.
    if isinstance(candidate_node, ast.Assign):
        return _assignment_identifiers(candidate_node.targets)
    # An annotated assignment exposes the same user-facing target shapes.
    if isinstance(candidate_node, ast.AnnAssign):
        return _target_identifiers(candidate_node.target)
    return []


def _argument_identifiers(arguments: ast.arguments) -> list[tuple[str, int]]:
    """Return names a user chose for positional and keyword-only parameters.

    Args:
        arguments: Parsed signature; empty parameter groups return no names.

    Returns:
        Parameter/line pairs in declaration order.
    """
    user_parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    # Every declared parameter can independently appear in the scan results.
    return [(parameter.arg, parameter.lineno) for parameter in user_parameters]


def _assignment_identifiers(assignment_targets: list[ast.expr]) -> list[tuple[str, int]]:
    """Collect user-visible names from every target in one assignment.

    Args:
        assignment_targets: Parsed targets; an empty list contributes no names.

    Returns:
        Flattened identifier/line pairs from simple and unpacked targets.
    """
    user_identifiers: list[tuple[str, int]] = []
    # Chained assignments let users bind more than one reviewed name at a line.
    for assignment_target in assignment_targets:
        user_identifiers.extend(_target_identifiers(assignment_target))
    return user_identifiers


def _target_identifiers(assignment_target: ast.expr) -> list[tuple[str, int]]:
    """Return simple names a user can rename in one assignment target.

    Args:
        assignment_target: Parsed target; attributes/subscripts return no names.

    Returns:
        Renameable identifier/line pairs, or empty for non-name targets.
    """
    # A direct assignment exposes one local name in the user's report.
    if isinstance(assignment_target, ast.Name):
        return [(assignment_target.id, assignment_target.lineno)]
    # Tuple/list unpacking exposes each simple child name independently.
    if isinstance(assignment_target, ast.Tuple | ast.List):
        return [
            (element.id, element.lineno)
            for element in assignment_target.elts
            if isinstance(element, ast.Name)
        ]
    return []
