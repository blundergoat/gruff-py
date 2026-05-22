"""``test-quality.sut-not-called`` — test body has no call to a function under test.

Heuristic: scan the test body for calls whose target is NOT one of:

- ``assert*`` (test framework assertions)
- ``pytest.*`` / ``unittest.*``
- ``mock.*`` / ``Mock`` / ``MagicMock`` / ``patch`` (mock interactions)
- builtins like ``print``, ``len``, ``isinstance``, ``hasattr``

If no such call exists, the test isn't exercising the system under test.
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
from gruffpy.rule.security._security_node_helper import call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    is_assertion_call,
    test_functions,
    walk_test_body,
)

_FRAMEWORK_LEAVES: frozenset[str] = frozenset(
    {
        "raises",
        "warns",
        "approx",
        "param",
        "fixture",
        "parametrize",
        "mark",
        "skip",
        "skipif",
    }
)
_MOCK_LEAVES: frozenset[str] = frozenset(
    {
        "Mock",
        "MagicMock",
        "AsyncMock",
        "patch",
        "patch_object",
        "PropertyMock",
        "create_autospec",
        "return_value",
        "side_effect",
        "assert_called",
        "assert_called_once",
        "assert_called_with",
        "assert_called_once_with",
        "assert_not_called",
        "reset_mock",
    }
)
_BUILTIN_LEAVES: frozenset[str] = frozenset(
    {"print", "len", "isinstance", "hasattr", "getattr", "setattr", "type", "id"}
)
# Schema-inspection accessors: a test that reads any of these IS exercising
# the schema declaration, even when there's no callable SUT.
# Source: 2026-05-23 healthkit dogfood (schema-contract tests asserting on
# `ReferralDetails.model_fields` etc.).
_SCHEMA_INSPECTION_ATTRS: frozenset[str] = frozenset(
    {"model_fields", "__annotations__", "__fields__", "model_config"}
)


class SutNotCalledRule(Rule):
    """Detect tests whose every call is a framework helper, builtin, or mock interaction."""

    ID = "test-quality.sut-not-called"

    def definition(self) -> RuleDefinition:
        """Describe the sut-not-called rule as a medium-confidence advisory.

        Medium confidence because identifying "SUT" without project context
        is impossible; the rule reports tests whose every call is a
        framework, builtin, or mock — a strong negative signal but not a
        proof.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="System under test never called",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tests with zero calls whose target is outside the framework/mock/builtin allowlist.

        A call counts as "SUT-like" when its target root isn't ``pytest``,
        ``unittest``, or ``mock``; its leaf isn't in the framework leaves
        (``raises``, ``fixture``, ``parametrize``, etc.), mock leaves
        (``Mock``, ``patch``, ``assert_called*``, etc.), or builtin leaves
        (``len``, ``isinstance``, ``getattr``); and it isn't an ``assert*``-
        prefixed method.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per test whose body never reaches non-framework code.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        module_names = _collect_module_level_names(unit.tree)
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            if _has_sut_call(fn, module_names):
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} never calls a non-framework, non-mock function "
                        f"— is the SUT exercised?"
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Make sure the test actually calls into the function or class "
                        "it claims to verify."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings


def _has_sut_call(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    module_names: frozenset[str],
) -> bool:
    for node in walk_test_body(fn):
        if _is_sut_call(node):
            return True
        if _is_module_level_name_read(node, module_names):
            return True
        if _is_schema_inspection_access(node):
            return True
    return False


def _is_sut_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if is_assertion_call(node):
        return False
    target = call_target_name(node)
    if target is None:
        return True
    return not _is_ignored_call_target(target)


def _is_ignored_call_target(target: str) -> bool:
    leaf = target.split(".")[-1]
    root = target.split(".")[0]
    if root in {"pytest", "unittest", "mock"}:
        return True
    if leaf in _FRAMEWORK_LEAVES or leaf in _MOCK_LEAVES or leaf in _BUILTIN_LEAVES:
        return True
    return leaf.startswith("assert")


def _is_module_level_name_read(node: ast.AST, module_names: frozenset[str]) -> bool:
    # A read of any name introduced at module level — whether by `import`,
    # `from X import Y`, or a module-level `NAME = ...` / `NAME: T = ...`
    # assignment — is a SUT touch. The test author put it at module level
    # for a reason: it's either the SUT itself or a fixture computed from
    # the SUT's source. Module-level locals like ``MODULE_SOURCE =
    # _read_metadata_builder_source()`` (2026-05-23 healthkit dogfood) IS
    # the SUT in schema/prompt-contract tests.
    return isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in module_names


def _is_schema_inspection_access(node: ast.AST) -> bool:
    # `Foo.model_fields` / `Foo.__annotations__` / `Foo.__fields__` — pydantic
    # / dataclass / TypedDict schema-inspection accessors. A test that reads
    # them is exercising the schema declaration regardless of receiver origin.
    return isinstance(node, ast.Attribute) and node.attr in _SCHEMA_INSPECTION_ATTRS


_TEST_FRAMEWORK_MODULE_ROOTS: frozenset[str] = frozenset(
    {"pytest", "unittest", "mock", "unittest.mock"}
)


def _collect_module_level_names(tree: ast.AST) -> frozenset[str]:
    # Collects (a) names bound by module-level imports, plus (b) names bound
    # by module-level ``X = ...`` / ``X: T = ...`` assignments. Both shapes
    # represent the test author's chosen "things this file is about" — reading
    # any of them from a test body counts as a SUT touch.
    #
    # Test-framework imports are excluded (e.g. `import pytest`, `from
    # unittest.mock import Mock`); they're already filtered by the
    # call-target allowlist, and counting them would defeat the rule.
    #
    # Module-body-only walk: nested-function locals and class-body
    # assignments are intentionally NOT collected. The rule is about test
    # bodies referencing module-scope things.
    names: set[str] = set()
    if not isinstance(tree, ast.Module):
        return frozenset(names)
    for stmt in tree.body:
        _collect_from_module_statement(stmt, names)
    # Also pick up ``if TYPE_CHECKING:`` imports — they participate in name
    # binding even when guarded.
    for walked in ast.walk(tree):
        if isinstance(walked, ast.If):
            for sub in walked.body:
                _collect_from_module_statement(sub, names)
    return frozenset(names)


def _collect_from_module_statement(node: ast.AST, names: set[str]) -> None:
    if isinstance(node, ast.Import):
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in _TEST_FRAMEWORK_MODULE_ROOTS:
                continue
            names.add(alias.asname or root)
    elif isinstance(node, ast.ImportFrom):
        if node.module is None or node.module == "__future__":
            return
        if node.module in _TEST_FRAMEWORK_MODULE_ROOTS:
            return
        if node.module.split(".")[0] in _TEST_FRAMEWORK_MODULE_ROOTS:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            names.add(alias.asname or alias.name)
    elif isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        names.add(node.target.id)
