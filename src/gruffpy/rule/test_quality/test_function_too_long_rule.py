"""``test-quality.test-function-too-long`` - test function exceeds line threshold.

Consumes the ``lines_for_size`` helper per ADR-002 so the line count
matches the size pillar's policy byte-for-byte.
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
from gruffpy.rule.size._lines import code_line_numbers, lines_for_size, parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class TestFunctionTooLongRule(Rule):
    """Flag test functions whose `lines_for_size` count exceeds the configured threshold."""

    ID = "test-quality.test-function-too-long"

    def definition(self) -> RuleDefinition:
        """Describe the test-function-too-long rule with a single 100-line default threshold.

        High confidence because line count is a deterministic structural
        metric; long tests reliably hide multiple behaviours and resist
        future maintenance. One value plus one severity per rubric (ADR-014).

        Returns:
            Definition with a single ``threshold`` of 100 at error severity.
        """
        return RuleDefinition(
            id=self.ID,
            name="Test function too long",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_enabled=False,
            default_threshold=100,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag test functions whose ``lines_for_size`` count exceeds the configured threshold.

        Uses the size-pillar's shared ``lines_for_size`` helper per ADR-002
        so the line metric stays consistent with other size rules. With the
        default same-value threshold a finding emits as the default severity
        (error); projects that split the ``warning``/``error`` keys can
        get severity escalation past the higher tier.

        A single GET/status/literal inline-snapshot response check is exempt.
        Extra operations and uncertain snapshot bindings retain length findings.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the ``warning``/
                ``error`` line-count thresholds.

        Returns:
            One finding per test whose size exceeds either threshold.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            lines = lines_for_size(fn, code_line_numbers(unit.source, unit.tree))
            threshold_match = settings.high_value_threshold_match(lines)
            if threshold_match is None or _is_literal_response_snapshot(fn, unit.tree):
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} is {lines} lines, above the {threshold_match.severity.value} threshold of {threshold_match.threshold}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=threshold_match.severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=("Split the test into focused cases or extract setup into a fixture."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "lines": lines,
                        "measuredValue": lines,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                    },
                ),
            )
        return findings


def _is_literal_response_snapshot(function: ast.FunctionDef | ast.AsyncFunctionDef, tree: ast.AST) -> bool:
    """Recognize one response check whose bulk is literal snapshot data.

    Args:
        function: Test function whose size crossed its configured limit.
        tree: Parsed file supplying the snapshot import and competing bindings.

    Returns:
        True for the supported single GET/status/snapshot shape.
    """
    body = function.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    match body:
        case [
            ast.Assign(
                targets=[ast.Name(id=response_name)],
                value=ast.Call(func=ast.Attribute(value=ast.Name(), attr="get"), args=[ast.Constant(value=str())], keywords=[]),
            ),
            ast.Assert(
                test=ast.Compare(
                    left=ast.Attribute(value=ast.Name(id=status_name), attr="status_code"),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant()],
                ),
                msg=None | ast.Attribute(value=ast.Name(), attr="text"),
            ),
            ast.Assert(
                test=ast.Compare(
                    left=ast.Call(func=ast.Attribute(value=ast.Name(id=json_name), attr="json"), args=[], keywords=[]),
                    ops=[ast.Eq()],
                    comparators=[ast.Call(func=ast.Name(id=snapshot_name), args=[expected], keywords=[])],
                ),
                msg=None,
            ),
        ] if response_name == status_name == json_name:
            return _is_literal_snapshot_data(expected) and _has_unambiguous_snapshot_import(tree, snapshot_name)
    return False


def _is_literal_snapshot_data(value: ast.AST) -> bool:
    """Keep computed expected values outside the snapshot-only exemption.

    Args:
        value: Snapshot argument to inspect without executing it.

    Returns:
        True when every node belongs to a literal data expression.
    """
    literal_nodes = (ast.Constant, ast.Dict, ast.List, ast.Tuple, ast.Set, ast.UnaryOp, ast.UAdd, ast.USub, ast.Load)
    return all(isinstance(node, literal_nodes) for node in ast.walk(value))


def _has_unambiguous_snapshot_import(tree: ast.AST, snapshot_name: str) -> bool:
    """Require a direct inline_snapshot import without competing static bindings.

    Args:
        tree: Parsed file containing the test and its import.
        snapshot_name: Callee spelling used by the response comparison.

    Returns:
        True for one module-level import with no other binding in the file.
    """
    if not isinstance(tree, ast.Module):
        return False
    imports = [
        (node, alias)
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
        if alias.name == "*" or (alias.asname or alias.name.split(".")[0]) == snapshot_name
    ]
    if len(imports) != 1:
        return False
    statement, alias = imports[0]
    if not (
        isinstance(statement, ast.ImportFrom)
        and statement in tree.body
        and statement.level == 0
        and statement.module == "inline_snapshot"
        and alias.name == "snapshot"
    ):
        return False
    return not any(
        (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del) and node.id == snapshot_name)
        or (isinstance(node, ast.arg) and node.arg == snapshot_name)
        or (not isinstance(node, ast.alias) and getattr(node, "name", None) == snapshot_name)
        or (isinstance(node, ast.MatchMapping) and node.rest == snapshot_name)
        for node in ast.walk(tree)
    )
