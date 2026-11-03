"""Single-character variable names outside common idioms.

Allowed by default: ``i``, ``j``, ``k``, ``n``, ``m``, ``x``, ``y``, ``z``,
``e`` (exception), ``_`` (throwaway), ``f`` (file). Configurable via
``acceptedShortNames`` per-rule option.

Scope: local assignments (Assign / AnnAssign). Function parameters are
intentionally NOT scanned - single-char params are common in math-flavoured
code (``def f(x, y, z): ...``). Test files are exempt; assertion fixtures and
table-driven rule tests routinely use tiny local placeholders where this
low-confidence style warning is noisy.
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

_DEFAULT_ACCEPTED: tuple[str, ...] = ("i", "j", "k", "n", "m", "x", "y", "z", "e", "_", "f")


class ShortVariableRule(Rule):
    """Detect single-character local variable assignments outside idiomatic loop and math names."""

    ID = "naming.short-variable"

    def definition(self) -> RuleDefinition:
        """Describe the short-variable rule with a configurable accepted-name list.

        Low confidence because single-character names are idiomatic in
        mathematical, loop-counter, and exception-handler contexts. The
        ``acceptedShortNames`` option lets teams expand the default
        (``i``/``j``/``k``/``n``/``m``/``x``/``y``/``z``/``e``/``_``/``f``).

        Returns:
            Definition for the short-variable rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Short variable name",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
            default_options={"acceptedShortNames": list(_DEFAULT_ACCEPTED)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag local single-character assignments not in the accepted-short-name set.

        Function parameters are intentionally not scanned (see module
        docstring - math-flavoured signatures use single-char params), and
        test files are skipped because fixture code routinely uses tiny
        placeholders.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the
                ``acceptedShortNames`` option.

        Returns:
            One finding per ``(name, line)`` short-name assignment.
        """
        if unit.tree is None:
            return []
        if _is_test_file(unit.file.display_path):
            return []
        definition = self.definition()
        accepted = _accepted_short_names(context, definition)
        return _short_variable_findings(unit, definition, accepted)


def _accepted_short_names(
    context: RuleContext,
    definition: RuleDefinition,
) -> frozenset[str]:
    """Resolve the short-name allowlist, falling back when its option is invalid.

    Args:
        context: Rule context used to resolve the definition's configured options.
        definition: Rule definition identifying which settings to read.

    Returns:
        Configured acceptedShortNames as a frozen set, or the built-in names when the option is absent or is not a list of strings.
    """
    settings = context.settings_for(definition)
    configured = settings.options.get("acceptedShortNames", list(_DEFAULT_ACCEPTED))
    if not isinstance(configured, list) or not all(isinstance(s, str) for s in configured):
        configured = list(_DEFAULT_ACCEPTED)
    return frozenset(configured)


def _short_variable_findings(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    accepted: frozenset[str],
) -> list[Finding]:
    """Report disallowed single-character assignment names once per name and source line.

    Args:
        unit: Source unit with a parsed AST; its display path is attached to each finding.
        definition: Rule identity, severity, confidence and pillar metadata for the findings.
        accepted: Exact name spellings exempt from this rule.

    Returns:
        Findings for qualifying assignments anywhere in the supplied tree, or an empty list when none qualify.

    Raises:
        AssertionError: If unit has no parsed AST.
    """
    assert unit.tree is not None
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for name, lineno in _assigned_names(unit.tree):
        if _should_report_short_name(name, lineno, accepted, seen):
            findings.append(_short_variable_finding(unit, definition, name, lineno))
    return findings


def _assigned_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Collect assignment names from every node in the supplied AST.

    Args:
        tree: Root of the subtree to traverse, including nested definitions.

    Returns:
        Name and source-line pairs from ordinary and annotated assignments in traversal order; duplicates are retained.
    """
    names: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        names.extend(_assignment_names(node))
    return names


def _assignment_names(node: ast.AST) -> list[tuple[str, int]]:
    """Extract direct target names from an ordinary or annotated assignment.

    Args:
        node: AST node to classify as an ordinary assignment, annotated assignment or unrelated node.

    Returns:
        Name and source-line pairs from supported targets, or an empty list for other nodes.
    """
    if isinstance(node, ast.Assign):
        return _assign_target_names(node)
    if isinstance(node, ast.AnnAssign):
        return _target_names(node.target)
    return []


def _assign_target_names(node: ast.Assign) -> list[tuple[str, int]]:
    """Collect direct names from all targets of an ordinary assignment.

    Args:
        node: Ordinary assignment whose target expressions are inspected in source order.

    Returns:
        Concatenated name and source-line pairs from _target_names, or an empty list if no target contributes a name.
    """
    names: list[tuple[str, int]] = []
    for target in node.targets:
        names.extend(_target_names(target))
    return names


def _target_names(target: ast.AST) -> list[tuple[str, int]]:
    """Extract a name or the immediate names in a tuple or list assignment target.

    Args:
        target: Assignment target to inspect without recursively unpacking nested targets.

    Returns:
        Name and source-line pairs for direct names; an empty list for unsupported shapes. Nested elements are not unpacked.
    """
    if isinstance(target, ast.Name):
        return [(target.id, target.lineno)]
    if isinstance(target, ast.Tuple | ast.List):
        return [(elt.id, elt.lineno) for elt in target.elts if isinstance(elt, ast.Name)]
    return []


def _should_report_short_name(
    name: str,
    lineno: int,
    accepted: frozenset[str],
    seen: set[tuple[str, int]],
) -> bool:
    """Accept an unseen, disallowed one-character name and remember its source occurrence.

    Args:
        name: Assigned identifier spelling to test against the allowlist.
        lineno: Source line distinguishing separate occurrences of the same name.
        accepted: Exact name spellings exempt from reporting.
        seen: Previously accepted name-and-line pairs; this pair is added only when the result is True.

    Returns:
        True for a new single-character name absent from accepted; False leaves seen unchanged.
    """
    if (name, lineno) in seen:
        return False
    if len(name) != 1 or name in accepted:
        return False
    seen.add((name, lineno))
    return True


def _short_variable_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    name: str,
    lineno: int,
) -> Finding:
    """Build a short-variable finding for a selected assignment occurrence.

    Args:
        unit: Source unit supplying the finding's display path.
        definition: Rule identity, severity, confidence and pillar metadata for the report.
        name: Disallowed single-character identifier to use as the symbol and metadata value.
        lineno: One-based source line used for both ends of the finding span.

    Returns:
        Finding identifying the variable and suggesting a descriptive name or an acceptedShortNames entry.
    """
    return Finding(
        rule_id=definition.id,
        message=f"Variable {name!r} is single-character; prefer a descriptive name.",
        file_path=unit.file.display_path,
        line=lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=lineno,
        symbol=name,
        remediation=f"Rename {name!r} or add it to ``acceptedShortNames`` if intentional.",
        secondary_pillars=definition.secondary_pillars,
        metadata={"identifier": name},
    )


def _is_test_file(display_path: str) -> bool:
    """Apply the short-variable rule's test-directory and root-test-file exemption.

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
