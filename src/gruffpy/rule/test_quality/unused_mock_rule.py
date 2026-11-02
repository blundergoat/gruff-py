"""``test-quality.unused-mock`` - mock variable created but never referenced afterwards.

Catches ``mock = Mock(); assert real_thing == 1`` where ``mock`` is never used.
The mock-detection extension to the helper finds the bindings; this rule scans
the test body for subsequent references.
"""

import ast
import symtable

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
from gruffpy.rule.test_quality._test_quality_node_helper import (
    find_mock_bindings,
    test_functions,
    walk_test_body,
)


class UnusedMockRule(Rule):
    """Detect mock variables created in a test body that are never referenced afterwards."""

    ID = "test-quality.unused-mock"

    def definition(self) -> RuleDefinition:
        """Describe the unused-mock rule as a high-confidence warning.

        High confidence because the rule looks for any Load-context
        reference to the mock's name in the test body - a mock with zero
        such references is dead test scaffolding.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unused mock",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tests whose mock binding name is never read elsewhere in the function body.

        Considers a mock "used" only when its name appears as a
        Load-context ``Name`` node (attribute access, function argument,
        etc.), including a read captured by a nested function. A nested
        local with the same name and plain reassignment don't count.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per test, listing the unused mock names in the
            message and metadata.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        function_tables: dict[tuple[str, int], symtable.SymbolTable] | None = None
        for fn, _scope in test_functions(unit):
            bindings = find_mock_bindings(fn)
            if not bindings:
                continue
            referenced = _referenced_names(fn, set(bindings))
            if set(bindings) - referenced and any(
                isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) for node in walk_test_body(fn)
            ):
                if function_tables is None:
                    function_tables = _function_tables(unit)
                table = function_tables.get((fn.name, fn.lineno))
                if table is not None:
                    referenced.update(symbol.get_name() for symbol in table.get_symbols() if symbol.get_name() in bindings and symbol.is_referenced())
                    referenced.update(_closure_references(table, set(bindings)))
            unused = sorted(set(bindings) - referenced)
            if not unused:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(f"Test {symbol!r} creates mock(s) never used afterwards: {unused}."),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=("Delete the unused mock, or assert on its interactions to prove the SUT calls it the way you expect."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"mocks": list(unused)},
                ),
            )
        return findings


def _referenced_names(fn: ast.FunctionDef | ast.AsyncFunctionDef, names: set[str]) -> set[str]:
    """Return candidate names read directly, including augmented-assignment targets.

    Args:
        fn: Test body walked while excluding nested function bodies.
        names: Candidate mock binding names to match without modifying the supplied set.

    Returns:
        New subset of names read in the walked body; empty when none are read.
    """
    found: set[str] = set()
    for node in walk_test_body(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in names:
            found.add(node.id)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id in names:
            found.add(node.target.id)
    return found


def _function_tables(unit: AnalysisUnit) -> dict[tuple[str, int], symtable.SymbolTable]:
    """Index compiler symbol tables without dropping enclosing lexical context.

    Args:
        unit: Parsed source whose full text supplies enclosing bindings.

    Returns:
        Function tables keyed by name and definition line, or an empty mapping
        when compiler-level syntax errors prevent lexical analysis.
    """
    # CPython marks x += value as assigned, not referenced. Add a same-line
    # read for symbol analysis only, retaining original scopes and line numbers.
    lines = unit.source.encode().splitlines(keepends=True)
    if unit.tree is not None:
        reads = [
            (node.lineno, node.col_offset, node.target.id)
            for node in ast.walk(unit.tree)
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name)
        ]
        for line, column, name in sorted(reads, reverse=True):
            current = lines[line - 1]
            lines[line - 1] = current[:column] + name.encode() + b"; " + current[column:]
    try:
        pending = [symtable.symtable(b"".join(lines).decode(), unit.file.display_path, "exec")]
    except SyntaxError:
        return {}
    tables = {}
    while pending:
        table = pending.pop()
        if table.get_type() == "function":
            tables[(table.get_name(), table.get_lineno())] = table
        pending.extend(table.get_children())
    return tables


def _closure_references(table: symtable.SymbolTable, names: set[str]) -> set[str]:
    """Find reads of candidate outer bindings through descendant scopes.

    Args:
        table: Symbol table whose child scopes may capture outer bindings.
        names: Candidate bindings still visible from the enclosing function.

    Returns:
        Names read through free-variable bindings, excluding local and global
        shadows and write-only nonlocal assignments.
    """
    found: set[str] = set()
    for child in table.get_children():
        symbols = {symbol.get_name(): symbol for symbol in child.get_symbols()}
        free = {name for name in names if name in symbols and symbols[name].is_free()}
        found.update(name for name in free if symbols[name].is_referenced())
        # Class attributes do not shadow enclosing bindings inside methods.
        visible = names if child.get_type() == "class" else free
        if visible:
            found.update(_closure_references(child, visible))
    return found
