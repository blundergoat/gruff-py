"""Discourage unclear abbreviations in identifiers.

The rule uses a curated blocklist rather than guessing from consonant
clusters. Users can allow project-standard abbreviations through
``allowlists.acceptedAbbreviations``.
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

_ABBREVIATION_BLOCKLIST: frozenset[str] = frozenset(
    {
        "attr",
        "cfg",
        "ctx",
        "defn",
        "func",
        "idx",
        "lst",
        "mgr",
        "msg",
        "params",
        "pkg",
        "pwd",
        "req",
        "res",
        "tmp",
        "tok",
        "usr",
        "var",
    }
)


class AbbreviationRule(Rule):
    """Flag identifiers containing curated unclear abbreviations like `ctx`, `cfg`, or `tmp`."""

    ID = "naming.abbreviation"

    def definition(self) -> RuleDefinition:
        """Describe the abbreviation rule.

        The blocklist is intentionally configurable because short forms such as
        ``ctx`` and ``msg`` are idiomatic in some codebases.

        Returns:
            Definition for the abbreviation rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Abbreviation",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag identifiers whose tokenised form contains a blocked abbreviation.

        Project-accepted abbreviations from
        ``allowlists.acceptedAbbreviations`` are subtracted before matching.
        Test files are skipped wholesale (fixtures routinely use ``tmp``,
        ``ctx``, ``msg``). Each blocked name fires at most once per file.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying accepted-abbreviation
                allowlists.

        Returns:
            One finding per unique identifier whose first blocked-abbreviation
            token is not accepted.
        """
        if unit.tree is None:
            return []
        if _is_test_file(unit.file.display_path):
            return []
        definition = self.definition()
        accepted = {abbr.lower() for abbr in context.config.accepted_abbreviations}
        findings: list[Finding] = []
        seen: set[str] = set()

        for node in ast.walk(unit.tree):
            for name, lineno, kind in _identifiers_in(node):
                if name in seen:
                    continue
                abbreviation = _blocked_abbreviation(name, accepted)
                if abbreviation is None:
                    continue
                seen.add(name)
                findings.append(
                    _finding_for_identifier(
                        definition,
                        unit.file.display_path,
                        name,
                        lineno,
                        kind,
                        abbreviation,
                    )
                )
        return findings


def _finding_for_identifier(
    definition: RuleDefinition,
    file_path: str,
    name: str,
    lineno: int,
    kind: str,
    abbreviation: str,
) -> Finding:
    """Build an abbreviation finding at the identifier occurrence selected by the rule.

    Args:
        definition: Rule identity, severity, confidence and pillar metadata for the report.
        file_path: Display path to attach to the finding.
        name: Identifier whose spelling contains the blocked token.
        lineno: One-based source line used for both ends of the finding span.
        kind: Identifier category used in the message and metadata.
        abbreviation: Blocked token to name in the message and metadata.

    Returns:
        Finding with the identifier as its symbol and the blocked abbreviation recorded in metadata.
    """
    return Finding(
        rule_id=definition.id,
        message=f"{kind.capitalize()} {name!r} uses unclear abbreviation {abbreviation!r}.",
        file_path=file_path,
        line=lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=lineno,
        symbol=name,
        remediation=("Rename the identifier with the full domain term or add a documented allowlist entry."),
        secondary_pillars=definition.secondary_pillars,
        metadata={"identifier": name, "kind": kind, "abbreviation": abbreviation},
    )


def _blocked_abbreviation(name: str, accepted: set[str]) -> str | None:
    """Select the first blocked token in an identifier that the project has not accepted.

    Args:
        name: Identifier to split into lowercase naming tokens.
        accepted: Lowercase abbreviation tokens permitted by the project.

    Returns:
        First blocklisted token absent from accepted, or None for a dunder name or when no token is blocked.
    """
    if _is_dunder(name):
        return None
    for token in lower_tokens(name):
        if token in _ABBREVIATION_BLOCKLIST and token not in accepted:
            return token
    return None


def _identifiers_in(node: ast.AST) -> list[tuple[str, int, str]]:
    """Collect abbreviation-check candidates from function declarations and assignments inside functions.

    Args:
        node: AST node from the rule traversal; assignment scope is determined through attached parent links.

    Returns:
        Name, source-line and kind tuples for the declaration or direct assignment targets; an empty list for other nodes.
    """
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return [(node.name, node.lineno, "function"), *_argument_identifiers(node.args)]
    if isinstance(node, ast.Assign) and _is_inside_function(node):
        return _assignment_identifiers(node.targets)
    if isinstance(node, ast.AnnAssign) and _is_inside_function(node):
        return _target_identifiers(node.target)
    return []


def _argument_identifiers(arguments: ast.arguments) -> list[tuple[str, int, str]]:
    """Collect the explicitly named positional and keyword-only parameters for abbreviation checking.

    Args:
        arguments: Function argument declaration whose positional-only, positional and keyword-only names are inspected.

    Returns:
        Name, source-line and parameter-kind tuples in declaration order; variadic arguments are not included.
    """
    all_args = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    return [(arg.arg, arg.lineno, "parameter") for arg in all_args]


def _assignment_identifiers(targets: list[ast.expr]) -> list[tuple[str, int, str]]:
    """Collect direct variable identifiers from each target of an ordinary assignment.

    Args:
        targets: Assignment targets, in the order written in the source.

    Returns:
        Concatenated name, source-line and variable-kind tuples from _target_identifiers, or an empty list if none qualify.
    """
    identifiers: list[tuple[str, int, str]] = []
    for target in targets:
        identifiers.extend(_target_identifiers(target))
    return identifiers


def _target_identifiers(target: ast.expr) -> list[tuple[str, int, str]]:
    """Extract a variable name or the immediate names in a tuple or list assignment target.

    Args:
        target: Assignment target to inspect without descending into nested unpacking.

    Returns:
        Name, source-line and variable-kind tuples; an empty list for other target shapes. Nested elements are not unpacked.
    """
    if isinstance(target, ast.Name):
        return [(target.id, target.lineno, "variable")]
    if isinstance(target, ast.Tuple | ast.List):
        return [(elt.id, elt.lineno, "variable") for elt in target.elts if isinstance(elt, ast.Name)]
    return []


def _is_inside_function(node: ast.AST) -> bool:
    """Check whether the parser-attached ancestor chain contains a function definition.

    Args:
        node: AST node whose attached parent links are followed.

    Returns:
        True when any ancestor is a synchronous or asynchronous function; False when the chain ends without one.
    """
    parent = getattr(node, "parent", None)
    while parent is not None:
        if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
            return True
        parent = getattr(parent, "parent", None)
    return False


def _is_dunder(name: str) -> bool:
    """Identify names wrapped in double underscores for the abbreviation exemption.

    Args:
        name: Identifier spelling to check.

    Returns:
        True when the name starts and ends with double underscores and has more than four characters; otherwise False.
    """
    return name.startswith("__") and name.endswith("__") and len(name) > 4


def _is_test_file(display_path: str) -> bool:
    """Apply the abbreviation rule's test-directory and root-test-file exemption.

    Args:
        display_path: Display path whose slashes and case are normalized before matching.

    Returns:
        True for a test or tests parent directory, or a root-level filename starting test_ and ending .py; otherwise False.
    """
    normalized = display_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if any(part in {"test", "tests"} for part in normalized.split("/")[:-1]):
        return True
    return "/" not in normalized and name.startswith("test_") and name.endswith(".py")
