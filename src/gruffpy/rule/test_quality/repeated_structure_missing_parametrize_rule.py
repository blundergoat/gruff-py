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

        Medium confidence reflects that normalizing case data can group distinct tests that share scaffolding.

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
        """Report similar tests as groups or individual findings according to groupFindings.

        Legacy mode ignores most constant values when grouping AST shapes; long or multiline strings retain content-sensitive hashes.

        Args:
            unit: Source file to inspect. A missing AST yields no findings. A first scope lookup caches the index and increments the shared counter.
            context: Rule execution context supplying the minGroupSize threshold, converted to an integer, and the groupFindings option.

        Returns:
            With groupFindings off or omitted, one finding per test in a legacy AST-shape group meeting minGroupSize.
            With it on, one per eligible group meeting minGroupSize, grouped by runner style, container, attribute key and body shape.
            Grouped mode skips table-driven tests and tests with fewer than two body statements after docstring removal.
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
                continue  # Call-decorated tests may already encode distinct cases, so legacy grouping leaves them alone.
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
    """Hash the full function AST for the legacy duplicate-test comparison.

    Name expressions and attribute accesses retain their spellings. Function and parameter declaration names are skipped.
    Most constants retain only their type. Long or newline-containing strings retain a value digest.

    Args:
        fn: Test declaration whose decorators, signature, docstring and body are traversed.

    Returns:
        SHA-256 hexadecimal digest of the legacy AST traversal, used to group structurally similar tests.
    """
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
    """Represent a constant for the legacy structural hash.

    Args:
        value: Literal value whose type, and for selected strings its contents, participate in the hash.

    Returns:
        Type marker, or a type-prefixed digest for strings with a newline or more than 80 characters.
    """
    if isinstance(value, str) and ("\n" in value or len(value) > 80):
        digest = hashlib.sha256(value.encode()).hexdigest()
        return f"Const:str:{digest}"
    return f"Const:{type(value).__name__}"


def _group_findings(unit: AnalysisUnit, definition: RuleDefinition, min_group: int) -> list[Finding]:
    """Report groups that share a lexical container, marks, body shape and runner so each finding can suggest a case table.
    Only recognized test cases with at least two statements after the docstring and no detected case table can join a group.
    A scope cache miss stores the parsed tree's function scopes and increments the shared computation counter.

    Args:
        unit: Parsed test file whose tests are compared; other files never join its groups.
        definition: This rule's definition, which supplies severity, pillar and confidence.
        min_group: Minimum number of tests required for a group finding, from the minGroupSize setting.

    Returns:
        One finding per qualifying group, anchored at its first member and ordered by that member's position. Empty if no group qualifies.
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
        definition: Rule metadata supplying the finding's identity, severity, pillar, tier, confidence and secondary pillars.
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
    """Order test functions by source line, then column.

    Args:
        fn: Test declaration whose position orders group members and findings.

    Returns:
        The line-and-column pair used for source ordering.
    """
    return (fn.lineno, fn.col_offset)


def _body_without_docstring(fn: _TestFunction) -> list[ast.stmt]:
    """Return the test's top-level statements after a leading docstring, which is documentation.

    Args:
        fn: Test declaration whose first statement is checked for a string docstring.

    Returns:
        A shallow slice without the leading docstring, or the original body list when there is no docstring.
    """
    first = fn.body[0] if fn.body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        return fn.body[1:]
    return fn.body


def _is_table_driven(fn: _TestFunction, body: list[ast.stmt]) -> bool:
    """Detect table-driven syntax that excludes a test from grouped findings.

    Args:
        fn: Test function whose marks, and those of its enclosing classes and module, are checked for parametrize.
        body: All top-level test statements, with the leading docstring omitted if present.

    Returns:
        True for a decorator or pytestmark containing a call whose final name ends in parametrize, a subTest call in the body,
        or a top-level loop over a literal list, tuple, dict or set. False otherwise.
    """
    scopes = [fn, *(parent for parent in parent_chain(fn) if isinstance(parent, ast.ClassDef | ast.Module))]
    marks = [mark for owner in scopes for mark in _marks(owner)]
    if any(isinstance(node, ast.Call) and _callee_name(node).endswith("parametrize") for mark in marks for node in ast.walk(mark)):
        return True
    if any(isinstance(node, ast.Call) and _callee_name(node) == "subTest" for stmt in body for node in ast.walk(stmt)):
        return True
    return any(isinstance(stmt, ast.For | ast.AsyncFor) and isinstance(stmt.iter, ast.List | ast.Tuple | ast.Dict | ast.Set) for stmt in body)


def _marks(owner: ast.AST) -> list[ast.expr]:
    """Collect decorators and values assigned directly to the bare name pytestmark in class or module bodies.

    Args:
        owner: AST owner; only class and module bodies are searched for pytestmark assignments.

    Returns:
        New list containing decorators first, followed by qualifying pytestmark values in body order.
    """
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
    """Extract the final name component from a call or callee expression.

    Args:
        node: Call, name or attribute inspected when recognizing parametrization or subTest syntax.

    Returns:
        Attribute name or identifier, or an empty string for unsupported expressions.
    """
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Attribute):
        return target.attr
    return target.id if isinstance(target, ast.Name) else ""


def _attribute_key(fn: _TestFunction) -> tuple[str, ...]:
    """Return the test's marks, then each enclosing class's from the inside out, with arguments and literals kept.

    The module's ``pytestmark`` is left out because every test in the file shares it.

    Args:
        fn: Test function whose marks and enclosing class marks define group compatibility.

    Returns:
        Serialized marks from the test and enclosing classes, preserving declaration order and visiting classes from inner to outer.
    """
    owners: list[ast.AST] = [fn, *(parent for parent in reversed(parent_chain(fn)) if isinstance(parent, ast.ClassDef))]
    return tuple(ast.dump(mark) for owner in owners for mark in _marks(owner))


def _container_key(fn: _TestFunction) -> tuple[ast.AST, ...]:
    """Keep distinct enclosing declarations apart, even when they have the same name.

    Args:
        fn: Test function with parser-attached parent links used to locate its lexical owners.

    Returns:
        Module, class and function ancestors in outer-to-inner order, retaining node identity to separate distinct declarations.
    """
    return tuple(parent for parent in parent_chain(fn) if isinstance(parent, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef))


def _body_shape(body: list[ast.stmt]) -> str:
    """Serialize test statements to compare bodies that could share a case table.

    Args:
        body: Top-level test statements after removal of a leading docstring.

    Returns:
        Newline-joined statement shapes. Function and class definitions and type statements retain their literal values.
        Dictionary keys, subscript selectors and strings with ASCII whitespace also retain literal values. Other constants are represented by kind.
    """
    return "\n".join(_shape_of(stmt) for stmt in body)


def _shape_of(node: object, *, preserve_literals: bool = False) -> str:
    """Serialize one AST value through its syntax fields only.

    Parent links sit outside the syntax fields, so serialization stays within the supplied value.
    A recursive traversal through those links, such as copy.deepcopy, can reach the whole module.

    Args:
        node: An AST node, a list of nodes, or a field value such as an identifier or operator flag.
        preserve_literals: When true, preserve every literal value in node and its descendants.

    Returns:
        A shape that always keeps literals in function, class and type alias declarations, dictionary keys and subscript selectors.
        It also keeps strings with ASCII whitespace. With preserve_literals false, other literals are represented by kind.
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
    """Classify a literal for group-comparison normalization.

    Args:
        value: Constant value whose category is preserved when its exact value may be ignored.

    Returns:
        Normalization label, with booleans separate from numbers and None labeled null; unrecognized values use their type name.
    """
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
