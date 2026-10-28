"""``test-quality.repeated-structure-missing-parametrize`` - repeated test groups.

By default, compare complete test bodies under family contract section 16 and
report one finding for each eligible group. Members share one lexical container,
matching decorators and ``pytestmark``, and at least two statements after the
docstring. Preserve whitespace-bearing text, literal keys and indices, and
declarations with their documentation and decorators. Normalize other literal
values by kind. Unittest methods never group with pytest tests.

Set ``groupFindings`` to false to retain legacy per-test structural-hash findings.
"""

import ast
import collections
import hashlib
from typing import Any

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import scopes_for_unit, test_functions
from gruffpy.rule.test_quality._test_quality_scope import TestScopeKind

GROUP_FINDINGS_OPTION = "groupFindings"
# conftest.py functions are fixtures and helpers, so they never join a group.
_TEST_KINDS = frozenset({TestScopeKind.BARE_TEST_FUNC, TestScopeKind.PYTEST_TEST_METHOD, TestScopeKind.UNITTEST_TEST_METHOD})

_TestFunction = ast.FunctionDef | ast.AsyncFunctionDef


class RepeatedStructureMissingParametrizeRule(Rule):
    """Detect groups of three or more test functions whose AST shape collapses to the same hash."""

    ID = "test-quality.repeated-structure-missing-parametrize"

    def definition(self) -> RuleDefinition:
        """Describe the repeated-structure rule with a ``minGroupSize`` threshold (default 3).

        Medium confidence because the structural hash ignores constant
        values to find shape duplicates - but legitimately distinct tests
        can occasionally hash the same when they share boilerplate scaffolding.

        Returns:
            Definition with the ``minGroupSize`` threshold key and the
            default-on ``groupFindings`` option.
        """
        return RuleDefinition(
            id=self.ID,
            name="Repeated structure without parametrize",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_thresholds={"minGroupSize": 3},
            default_options={GROUP_FINDINGS_OPTION: True},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Report eligible groups, or per-test findings when ``groupFindings`` is false.

        Legacy mode hashes each test body's structural skeleton (node types, names,
        attributes - but not constant values) and groups by hash; skips
        tests that already have a call-style decorator (they're presumed
        intentionally individualised).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the ``minGroupSize``
                numeric threshold and the ``groupFindings`` option.

        Returns:
            One finding per test belonging to a shape-equivalent group whose
            size meets the threshold; with ``groupFindings`` on, one finding
            per group instead.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        min_group = int(settings.numeric_threshold("minGroupSize"))
        if settings.options.get(GROUP_FINDINGS_OPTION, False):
            return _group_findings(unit, definition, min_group)
        findings: list[Finding] = []
        groups: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = collections.defaultdict(list)
        for fn, _scope in test_functions(unit):
            if any(isinstance(d, ast.Call) for d in fn.decorator_list):
                continue  # decorated tests are already structured
            groups[_shape_hash(fn)].append(fn)
        for fns in groups.values():
            if len(fns) < min_group:
                continue
            for fn in fns:
                is_unittest = scopes_for_unit(unit)[fn].kind == TestScopeKind.UNITTEST_TEST_METHOD
                table_style = "self.subTest(...)" if is_unittest else "@pytest.mark.parametrize"
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(f"Test {symbol!r} shares a body shape with {len(fns) - 1} other test(s) - candidate for {table_style}."),
                        file_path=unit.file.display_path,
                        line=fn.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=fn.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Collapse the duplicated tests into one `self.subTest(...)` loop over the differing values."
                            if is_unittest
                            else "Collapse the duplicated tests into one parametrised test that iterates the differing values."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"groupSize": len(fns)},
                    ),
                )
        return findings


def _shape_hash(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Hash the *structural* shape of a function body, ignoring constant values."""
    parts: list[str] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant):
            parts.append(_constant_shape(node.value))
        elif isinstance(node, ast.Name):
            parts.append(f"Name:{node.id}")
        elif isinstance(node, ast.Attribute):
            parts.append(f"Attribute:{node.attr}")
        else:
            parts.append(type(node).__name__)
    blob = "|".join(parts).encode()
    return hashlib.sha256(blob).hexdigest()


def _constant_shape(value: Any) -> str:
    if isinstance(value, str) and ("\n" in value or len(value) > 80):
        digest = hashlib.sha256(value.encode()).hexdigest()
        return f"Const:str:{digest}"
    return f"Const:{type(value).__name__}"


def _group_findings(unit: AnalysisUnit, definition: RuleDefinition, min_group: int) -> list[Finding]:
    """Report one finding per group of matching tests, as family contract section 16 defines them.

    Args:
        unit: Parsed test file whose tests are compared; other files never join its groups.
        definition: This rule's definition, which supplies severity, pillar and confidence.
        min_group: Smallest group that reports; ``minGroupSize`` keeps its meaning here.

    Returns:
        One finding per qualifying group, anchored at its first member, ordered by that member's position.
    """
    # The runner is part of the key: a group's advice names one table idiom, and unittest and pytest each need their own.
    groups: dict[tuple[bool, tuple[ast.AST, ...], tuple[str, ...], str], list[_TestFunction]] = collections.defaultdict(list)
    for fn, scope in test_functions(unit):
        body = _body_without_docstring(fn)
        if scope.kind not in _TEST_KINDS or len(body) < 2 or _is_table_driven(fn, body):
            continue
        groups[(scope.kind is TestScopeKind.UNITTEST_TEST_METHOD, _container_key(fn), _attribute_key(fn), _body_shape(body))].append(fn)
    reported = [(unittest, sorted(members, key=_position)) for (unittest, _, _, _), members in groups.items() if len(members) >= min_group]
    return [
        _group_finding(unit, definition, members, unittest=unittest)
        for unittest, members in sorted(reported, key=lambda group: _position(group[1][0]))
    ]


def _group_finding(unit: AnalysisUnit, definition: RuleDefinition, members: list[_TestFunction], *, unittest: bool) -> Finding:
    """Build the one finding for a group, listing every member so a reviewer can find them all.

    Args:
        unit: Test file that holds the group.
        definition: This rule's definition.
        members: Group members in source order; the first is the anchor.
        unittest: Whether the members are unittest methods, which picks ``subTest`` over ``parametrize``.

    Returns:
        Finding anchored at the first member, naming the table idiom and asking for a label per case.
    """
    named = [(qualified_symbol(fn, parent_chain(fn)), fn.lineno) for fn in members]
    listed = ", ".join(f"{symbol!r} (line {line})" for symbol, line in named)
    idiom = "test method that loops over the cases in `self.subTest(...)`" if unittest else "`@pytest.mark.parametrize` test"
    return Finding(
        rule_id=definition.id,
        message=f"{len(members)} tests share one body shape: {listed} - fold them into one {idiom} with a descriptive label per case.",
        file_path=unit.file.display_path,
        line=members[0].lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=members[0].end_lineno,
        symbol=named[0][0],
        remediation=(
            f"Fold the {len(members)} tests into one {idiom}, giving each case a descriptive label so a failure still names the scenario it broke."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"groupSize": len(members), "members": [{"symbol": symbol, "line": line} for symbol, line in named]},
    )


def _position(fn: _TestFunction) -> tuple[int, int]:
    return (fn.lineno, fn.col_offset)


def _body_without_docstring(fn: _TestFunction) -> list[ast.stmt]:
    """Return the test's top-level statements after a leading docstring, which is documentation."""
    first = fn.body[0] if fn.body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        return fn.body[1:]
    return fn.body


def _is_table_driven(fn: _TestFunction, body: list[ast.stmt]) -> bool:
    """Return whether a test already runs its cases from a table, which section 16 leaves out.

    Args:
        fn: Test function whose marks, and those of its enclosing classes and module, are checked for ``parametrize``.
        body: Its statements after the docstring.

    Returns:
        True for a ``parametrize`` decorator or ``pytestmark`` on the test, a class or the module, any ``subTest`` call,
        or a top-level loop over an inline literal table.
    """
    scopes = [fn, *(parent for parent in parent_chain(fn) if isinstance(parent, ast.ClassDef | ast.Module))]
    marks = [mark for owner in scopes for mark in _marks(owner)]
    if any(isinstance(node, ast.Call) and _callee_name(node).endswith("parametrize") for mark in marks for node in ast.walk(mark)):
        return True
    if any(isinstance(node, ast.Call) and _callee_name(node) == "subTest" for stmt in body for node in ast.walk(stmt)):
        return True
    return any(isinstance(stmt, ast.For | ast.AsyncFor) and isinstance(stmt.iter, ast.List | ast.Tuple | ast.Dict | ast.Set) for stmt in body)


def _marks(owner: ast.AST) -> list[ast.expr]:
    """Return an owner's decorators, then for a class or module the value of each ``pytestmark`` assignment in its body."""
    marks: list[ast.expr] = list(getattr(owner, "decorator_list", []))
    # A function's own body is test code; only class and module bodies declare marks for the tests they hold.
    if isinstance(owner, ast.ClassDef | ast.Module):
        for stmt in owner.body:
            if not isinstance(stmt, ast.Assign | ast.AnnAssign) or stmt.value is None:
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in targets):
                marks.append(stmt.value)
    return marks


def _callee_name(node: ast.expr) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Attribute):
        return target.attr
    return target.id if isinstance(target, ast.Name) else ""


def _attribute_key(fn: _TestFunction) -> tuple[str, ...]:
    """Return the test's marks, then each enclosing class's from the inside out, with arguments and literals kept.

    The module's ``pytestmark`` is left out because every test in the file shares it.
    """
    owners: list[ast.AST] = [fn, *(parent for parent in reversed(parent_chain(fn)) if isinstance(parent, ast.ClassDef))]
    return tuple(ast.dump(mark) for owner in owners for mark in _marks(owner))


def _container_key(fn: _TestFunction) -> tuple[ast.AST, ...]:
    """Keep distinct enclosing declarations apart, even when they have the same name."""
    return tuple(parent for parent in parent_chain(fn) if isinstance(parent, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef))


def _body_shape(body: list[ast.stmt]) -> str:
    """Serialize statements, retaining text payloads, keys and indices as section 16 requires."""
    return "\n".join(_shape_of(stmt) for stmt in body)


def _shape_of(node: object, *, preserve_literals: bool = False) -> str:
    """Serialize one AST value through its syntax fields only.

    ``ast.iter_fields`` never yields the ``parent`` link the parser attaches to every node, so the cost stays
    proportional to this statement; anything that follows that link, such as ``copy.deepcopy``, walks the whole module.

    Args:
        node: An AST node, a list of nodes, or a field value such as an identifier or operator flag.
        preserve_literals: Keep literal values within a declaration, container key or index/slice expression.

    Returns:
        A shape retaining significant literal values; other literals match only within their kind.
    """
    # Declarations are structure rather than case data; TypeAlias is available from Python 3.12.
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) or type(node).__name__ == "TypeAlias":
        preserve_literals = True
    if isinstance(node, ast.Constant):
        if preserve_literals or isinstance(node.value, str) and any(character in " \t\n\r\f\v" for character in node.value):
            return repr(node.value)
        return f"<{_literal_kind(node.value)}>"
    if isinstance(node, ast.AST):
        fields = []
        for name, value in ast.iter_fields(node):
            selector = isinstance(node, ast.Dict) and name == "keys" or isinstance(node, ast.Subscript) and name == "slice"
            fields.append(f"{name}={_shape_of(value, preserve_literals=preserve_literals or selector)}")
        return f"{type(node).__name__}(" + ",".join(fields) + ")"
    if isinstance(node, list):
        return "[" + ",".join(_shape_of(item, preserve_literals=preserve_literals) for item in node) + "]"
    return repr(node)


def _literal_kind(value: object) -> str:
    # bool is checked before int because it subclasses it.
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    if isinstance(value, int | float | complex):
        return "number"
    if isinstance(value, bytes):
        return "bytes"
    return "string" if isinstance(value, str) else type(value).__name__
