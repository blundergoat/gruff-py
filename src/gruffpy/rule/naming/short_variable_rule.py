"""Flag cryptic single-character variable assignments during `gruff-py analyse` and `hook` runs.

Use this rule to nudge developers and coding agents away from throwaway local names like `a = fetch_user()` while keeping common idioms quiet.
Teams can customise the allowlist with `acceptedShortNames` in `.gruff-py.yaml` or `pyproject.toml`.

- Allowed by default: `i`, `j`, `k`, `n`, `m`, `x`, `y`, `z`, `e`, `_`, and `f`, plus PEP 484 `TypeVar`, `ParamSpec`, and `TypeVarTuple` bindings.
- Out of scope: function parameters (common in math signatures) and test files (where tiny fixture placeholders are idiomatic).
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
_TYPE_PARAMETER_CONSTRUCTORS: frozenset[str] = frozenset({"TypeVar", "ParamSpec", "TypeVarTuple"})
_TYPING_MODULES: frozenset[str] = frozenset({"typing", "typing_extensions"})


class ShortVariableRule(Rule):
    """Detect single-character local variable assignments outside idiomatic loop, math, and typing names.

    The analyser runs this rule across production Python files so reviewers spot opaque one-letter locals before merging.
    Override `acceptedShortNames` per project when domain conventions favour extra single-letter symbols.
    """

    ID = "naming.short-variable"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata and default `acceptedShortNames` list for the registry and `list-rules`.

        Returns:
            Definition for the short-variable advisory rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Short variable name",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
            default_options={"acceptedShortNames": list(_DEFAULT_ACCEPTED)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan one parsed production Python file for disallowed single-character variable assignments.

        Function parameters and test files are skipped so math signatures and tiny test fixtures never clutter CLI output.

        Args:
            unit: Parsed source file to inspect; `unit.tree` is None for non-Python files, syntax errors, or budget-skipped files.
            context: Rule execution context supplying the user's `acceptedShortNames` list when configured.

        Returns:
            One finding per `(name, line)` short-name assignment; an empty list when the AST is absent, the file is a test, or all names are allowed.
        """
        # Non-Python files, syntax failures, and budget-skipped files have no AST to walk.
        if unit.tree is None:
            return []
        # Skip test files because fixture builders and assertion helpers routinely use tiny local placeholders.
        if _is_test_file(unit.file.display_path):
            return []
        definition = self.definition()
        accepted = _accepted_short_names(context, definition)
        return _short_variable_findings(unit, definition, accepted)


def _accepted_short_names(
    context: RuleContext,
    definition: RuleDefinition,
) -> frozenset[str]:
    """Resolve the user's `acceptedShortNames` allowlist, falling back to built-in idioms if the option is malformed.

    Args:
        context: Rule context carrying merged defaults and any per-project rule options.
        definition: Rule definition naming the option lookup key.

    Returns:
        Frozen set of exempt names; an explicit empty list exempts nothing, while an absent or non-string-list value restores built-in defaults.
    """
    settings = context.settings_for(definition)
    configured = settings.options.get("acceptedShortNames", list(_DEFAULT_ACCEPTED))
    # Fall back to built-in idioms if a config file passes a non-list or non-string value so the scan does not crash.
    if not isinstance(configured, list) or not all(isinstance(entry, str) for entry in configured):
        configured = list(_DEFAULT_ACCEPTED)
    return frozenset(configured)


def _short_variable_findings(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    accepted: frozenset[str],
) -> list[Finding]:
    """Report each disallowed single-character assignment at most once per `(name, line)` in the file.

    Args:
        unit: Parsed source file whose display path attaches to emitted findings; `unit.tree` must not be None.
        definition: Rule metadata attached to every emitted finding.
        accepted: Exact variable spellings the user or defaults allow.

    Returns:
        Findings for qualifying assignments in traversal order; an empty list when every assignment uses an allowed or multi-letter name.

    Raises:
        AssertionError: When `unit.tree` is None (prevented by the guard in `analyse`).
    """
    assert unit.tree is not None
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    # Inspect every ordinary and annotated assignment target and deduplicate chained targets on the same line.
    for name, lineno in _assigned_names(unit.tree):
        # Emit a finding only for unseen single-character names outside the user's allowlist.
        if _should_report_short_name(name, lineno, accepted, seen):
            findings.append(_short_variable_finding(unit, definition, name, lineno))
    return findings


def _assigned_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Collect assigned variable names and line numbers across the entire module AST.

    Args:
        tree: Root of the parsed Python module, including nested functions and classes.

    Returns:
        Name and one-based line pairs from ordinary and annotated assignments in walk order; an empty list when no assignments exist.
    """
    names: list[tuple[str, int]] = []
    # Walk every AST node so locals inside functions, methods, and class bodies are all checked.
    for node in ast.walk(tree):
        names.extend(_assignment_names(node))
    return names


def _assignment_names(node: ast.AST) -> list[tuple[str, int]]:
    """Extract direct target names from one assignment node, skipping PEP 484 type-parameter declarations.

    Args:
        node: AST node being classified as an ordinary assignment, an annotated assignment, or another construct.

    Returns:
        Name and line pairs for scannable targets; an empty list for type-parameter bindings (such as `T = TypeVar("T")`) or non-assignment nodes.
    """
    # Ordinary assignments like `q = fetch()` are scanned unless the right-hand side builds a typing parameter like `T = TypeVar("T")`.
    if isinstance(node, ast.Assign):
        if _is_type_parameter_call(node.value):
            return []
        return _assign_target_names(node)
    # Annotated assignments like `q: int = 1` follow the same typing-parameter exemption.
    if isinstance(node, ast.AnnAssign):
        if _is_type_parameter_call(node.value):
            return []
        return _target_names(node.target)
    return []


def _is_type_parameter_call(value: ast.expr | None) -> bool:
    """Check whether an assigned expression constructs a PEP 484 `TypeVar`, `ParamSpec`, or `TypeVarTuple`.

    Lets developers declare conventional single-letter type variables (`T`, `K`, `V`, `P`) without triggering short-variable noise.

    Args:
        value: Right-hand side expression of an assignment, or None for a bare annotation such as `x: int`.

    Returns:
        True for bare or `typing`/`typing_extensions`-qualified type-parameter constructors; False for None or any other expression.
    """
    # Bare annotations (`value is None`) and non-call expressions cannot be type-parameter constructor calls.
    if not isinstance(value, ast.Call):
        return False
    callee = value.func
    # Match direct imports such as `from typing import TypeVar; T = TypeVar("T")`.
    if isinstance(callee, ast.Name):
        return callee.id in _TYPE_PARAMETER_CONSTRUCTORS
    # Match module-qualified calls such as `typing.TypeVar("T")` or `typing_extensions.ParamSpec("P")`.
    if isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name):
        return callee.value.id in _TYPING_MODULES and callee.attr in _TYPE_PARAMETER_CONSTRUCTORS
    return False


def _assign_target_names(node: ast.Assign) -> list[tuple[str, int]]:
    """Collect direct variable names across all chained targets of an ordinary assignment (such as `a = b = 1`).

    Args:
        node: Ordinary assignment node whose targets are inspected in source order.

    Returns:
        Concatenated `(name, lineno)` pairs from each target; an empty list when targets are only attributes or subscripts.
    """
    names: list[tuple[str, int]] = []
    # Check every target in chained assignments so `a = b = value` inspects both `a` and `b`.
    for target in node.targets:
        names.extend(_target_names(target))
    return names


def _target_names(target: ast.AST) -> list[tuple[str, int]]:
    """Extract a bare variable name or the top-level names inside a tuple/list unpacking target.

    Args:
        target: Assignment target node; attributes, subscripts, and deeper nested unpackings are skipped.

    Returns:
        `(name, lineno)` pairs for direct local names; an empty list for unsupported target shapes.
    """
    # Direct binding such as `q = compute()`.
    if isinstance(target, ast.Name):
        return [(target.id, target.lineno)]
    # Flat tuple or list unpacking such as `a, b = pair`.
    if isinstance(target, ast.Tuple | ast.List):
        return [(element.id, element.lineno) for element in target.elts if isinstance(element, ast.Name)]
    return []


def _should_report_short_name(
    name: str,
    lineno: int,
    accepted: frozenset[str],
    seen: set[tuple[str, int]],
) -> bool:
    """Decide whether an assigned name should produce a finding and record it so the same line is not reported twice.

    Args:
        name: Assigned variable identifier to check.
        lineno: One-based line number distinguishing separate assignments to the same name.
        accepted: Allowed single-character spellings from defaults or user config.
        seen: Mutable set of already-reported `(name, lineno)` pairs; updated only when returning True.

    Returns:
        True for an unseen disallowed single-character variable; False leaves `seen` unchanged.
    """
    # Skip duplicate appearances of the same name on the same line (for example `q = q = 1`).
    if (name, lineno) in seen:
        return False
    # Ignore multi-character identifiers and single-character names the developer or defaults explicitly allow.
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
