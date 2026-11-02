"""``security.disabled-ssl-verification`` - explicit SSL/TLS verify disablement.

Catches:

- ``requests.get/post/.../request(..., verify=False)``
- ``ssl._create_unverified_context()``
- ``urllib3.disable_warnings()``
"""

import ast
from dataclasses import dataclass

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
from gruffpy.rule.security._security_node_helper import (
    call_keyword,
    call_target_name,
    is_false_constant,
)

_REQUESTS_METHODS: frozenset[str] = frozenset({"get", "post", "put", "delete", "patch", "head", "options", "request"})
_SOURCE_NEEDLES: tuple[str, ...] = ("verify", "_create_unverified_context", "disable_warnings")
_TLS_REMEDIATION = "Use a properly verified TLS context. If you need a custom trust store, configure CA bundles instead of disabling verification."


class DisabledSslVerificationRule(Rule):
    """Find code paths that explicitly disable TLS certificate verification."""

    ID = "security.disabled-ssl-verification"

    def definition(self) -> RuleDefinition:
        """Describe the disabled-SSL-verification rule as a high-confidence ERROR.

        ERROR severity because disabling TLS verification on outbound
        requests defeats certificate-pinning and exposes the caller to
        active MITM attacks; high confidence because the matched shapes
        (``verify=False``, ``_create_unverified_context``,
        ``disable_warnings``) are deliberate, not incidental.

        Returns:
            Definition for the disabled-SSL-verification rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Disabled SSL verification",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag explicit TLS-verification disablement across requests / ssl / urllib3.

        Three call shapes trigger findings: ``requests.<method>(verify=...)``
        with literal ``False`` or a same-scope ``False`` alias;
        ``ssl._create_unverified_context()``; and
        ``urllib3.disable_warnings()``. Alias tracking is reset at function,
        async-function, and class boundaries to avoid leaking state across
        unrelated scopes.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per TLS-verification-disabling call site.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        visitor = _DisabledSslVerificationVisitor(unit, definition)
        visitor.visit(unit.tree)
        return visitor.findings


class _DisabledSslVerificationVisitor(ast.NodeVisitor):
    """AST visitor that tracks false aliases within each lexical scope."""

    def __init__(self, unit: AnalysisUnit, definition: RuleDefinition) -> None:
        self._unit = unit
        self._definition = definition
        self._false_aliases: set[str] = set()
        self.findings: list[Finding] = []

    def visit_Module(self, node: ast.Module) -> None:
        """Visit a module body with a fresh alias set.

        Args:
            node: Module node to inspect.
        """
        self._visit_scope_body(node.body, false_aliases=set())

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a function body with aliases isolated from outer scope.

        Args:
            node: Function definition to inspect.
        """
        self._visit_scope_body(node.body, false_aliases=set())

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit an async function body with aliases isolated from outer scope.

        Args:
            node: Async function definition to inspect.
        """
        self._visit_scope_body(node.body, false_aliases=set())

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class body with aliases isolated from outer scope.

        Args:
            node: Class definition to inspect.
        """
        self._visit_scope_body(node.body, false_aliases=set())

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect a call expression for TLS verification disablement.

        Args:
            node: Call expression to inspect.
        """
        target = call_target_name(node)
        if target is not None:
            reason, source_label = _ssl_verification_disabled_reason(
                target,
                node,
                self._false_aliases,
            )
            if reason is not None:
                self.findings.append(
                    _finding(
                        _SslFindingParts(
                            unit=self._unit,
                            definition=self._definition,
                            node=node,
                            target=target,
                            reason=reason,
                            source_label=source_label,
                        )
                    )
                )
        self.generic_visit(node)

    def _visit_scope_body(self, body: list[ast.stmt], false_aliases: set[str]) -> None:
        """Visit a statement sequence with a private copy of its initial aliases.

        Calls found during traversal are appended to the visitor's findings.

        Args:
            body: Statements to visit in source order.
            false_aliases: Initial false-value names, copied so the caller's set is unchanged.
        """
        aliases = set(false_aliases)
        for stmt in body:
            self._visit_scope_statement(stmt, aliases)

    def _visit_scope_statement(self, stmt: ast.stmt, aliases: set[str]) -> None:
        """Dispatch a statement while carrying the current false-value aliases.

        Specialized handlers preserve scope boundaries; other statements use the supplied aliases during normal traversal.

        Args:
            stmt: Statement whose calls and bindings are inspected.
            aliases: Current scope's mutable alias set, updated by handled bindings and branches.
        """
        if self._did_visit_definition_or_assignment(stmt, aliases):
            return
        if self._did_visit_conditional_or_branching_statement(stmt, aliases):
            return
        self._visit_with_aliases(stmt, aliases)

    def _did_visit_definition_or_assignment(self, stmt: ast.stmt, aliases: set[str]) -> bool:
        """Handle definitions and assignments before generic statement traversal.

        Args:
            stmt: Statement to dispatch when it defines a scope or assigns a value.
            aliases: Mutable current-scope aliases to invalidate or record.

        Returns:
            True when a specialized handler visited the statement; false when dispatch remains necessary.
        """
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            self._visit_nested_scope(stmt, aliases)
            return True
        if isinstance(stmt, ast.Assign):
            self._visit_assignment(stmt, aliases)
            return True
        if isinstance(stmt, ast.AnnAssign):
            self._visit_annotated_assignment(stmt, aliases)
            return True
        if isinstance(stmt, ast.AugAssign):
            self._visit_augmented_assignment(stmt, aliases)
            return True
        return False

    def _did_visit_conditional_or_branching_statement(
        self,
        stmt: ast.stmt,
        aliases: set[str],
    ) -> bool:
        """Handle conditional and loop or exception suites with branch-local aliases.

        Args:
            stmt: Statement to check for an if, loop, or try suite.
            aliases: Mutable outer aliases from which branch state is copied and later invalidated.

        Returns:
            True when the statement was handled; false for unsupported statement shapes.
        """
        if isinstance(stmt, ast.If):
            self._visit_if_statement(stmt, aliases)
            return True
        if isinstance(stmt, ast.For | ast.AsyncFor | ast.While | ast.Try):
            self._visit_branching_scope_statement(stmt, aliases)
            return True
        return False

    def _visit_nested_scope(
        self,
        stmt: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        aliases: set[str],
    ) -> None:
        """Visit a nested definition without inheriting outer false-value aliases.

        Args:
            stmt: Function or class definition whose body starts a fresh alias scope.
            aliases: Outer alias set from which the definition's bound name is removed.
        """
        aliases.discard(stmt.name)
        self.visit(stmt)

    def _visit_assignment(self, stmt: ast.Assign, aliases: set[str]) -> None:
        """Inspect an assigned value before recording its new false-value bindings.

        Args:
            stmt: Assignment whose value is visited before its targets change state.
            aliases: Current alias set, mutated to reflect the assigned value.
        """
        self._visit_with_aliases(stmt.value, aliases)
        self._record_assignment(stmt.targets, stmt.value, aliases)

    def _visit_annotated_assignment(self, stmt: ast.AnnAssign, aliases: set[str]) -> None:
        """Inspect an annotated assignment and refresh its target's alias state.

        Args:
            stmt: Annotated assignment; an absent value still invalidates its target aliases.
            aliases: Current alias set, mutated after any value is visited.
        """
        if stmt.value is not None:
            self._visit_with_aliases(stmt.value, aliases)
        self._record_assignment([stmt.target], stmt.value, aliases)

    def _visit_augmented_assignment(self, stmt: ast.AugAssign, aliases: set[str]) -> None:
        """Inspect an augmented value and invalidate aliases for its targets.

        Args:
            stmt: Augmented assignment whose value is inspected for calls.
            aliases: Current alias set from which the assigned target names are removed.
        """
        self._visit_with_aliases(stmt.value, aliases)
        aliases.difference_update(_target_names(stmt.target))

    def _visit_if_statement(self, stmt: ast.If, aliases: set[str]) -> None:
        """Inspect an if test and isolate alias changes in each branch.

        Each branch starts with a copy of the incoming aliases, so branch assignments do not establish outer aliases.

        Args:
            stmt: Conditional whose test, body, and alternative suite are visited.
            aliases: Outer aliases; names assigned anywhere in the conditional are removed afterward.
        """
        self._visit_with_aliases(stmt.test, aliases)
        self._visit_scope_body(stmt.body, set(aliases))
        self._visit_scope_body(stmt.orelse, set(aliases))
        aliases.difference_update(_assigned_names(stmt))

    def _visit_branching_scope_statement(self, stmt: ast.stmt, aliases: set[str]) -> None:
        """Visit a loop or try statement and invalidate its outer assigned names.

        Args:
            stmt: Loop or try statement delegated to the branching visitor.
            aliases: Outer alias set from which names assigned within the statement are removed.
        """
        self._visit_branching_statement(stmt, aliases)
        aliases.difference_update(_assigned_names(stmt))

    def _visit_branching_statement(self, stmt: ast.stmt, aliases: set[str]) -> None:
        """Inspect supported loop and exception suites using independent alias copies.

        Loop iterables or tests are inspected before their suites; try bodies, handlers, alternatives, and finalizers each receive separate copies.

        Args:
            stmt: For, async-for, while, or try statement; other shapes receive no traversal here.
            aliases: Initial aliases copied for each suite and used while inspecting loop expressions.
        """
        if isinstance(stmt, ast.For | ast.AsyncFor):
            self._visit_with_aliases(stmt.iter, aliases)
            self._visit_scope_body(stmt.body, set(aliases))
            self._visit_scope_body(stmt.orelse, set(aliases))
            return
        if isinstance(stmt, ast.While):
            self._visit_with_aliases(stmt.test, aliases)
            self._visit_scope_body(stmt.body, set(aliases))
            self._visit_scope_body(stmt.orelse, set(aliases))
            return
        if isinstance(stmt, ast.Try):
            self._visit_scope_body(stmt.body, set(aliases))
            for handler in stmt.handlers:
                self._visit_scope_body(handler.body, set(aliases))
            self._visit_scope_body(stmt.orelse, set(aliases))
            self._visit_scope_body(stmt.finalbody, set(aliases))

    def _visit_with_aliases(self, node: ast.AST, aliases: set[str]) -> None:
        """Visit a subtree with temporary alias state and restore the prior state.

        The visitor's previous alias reference is restored in finally, including when traversal fails.

        Args:
            node: Syntax subtree to visit using the supplied aliases.
            aliases: Alias set exposed to nested call checks during this visit.
        """
        previous = self._false_aliases
        self._false_aliases = aliases
        try:
            self.visit(node)
        finally:
            self._false_aliases = previous

    @staticmethod
    def _record_assignment(
        targets: list[ast.expr],
        value: ast.expr | None,
        aliases: set[str],
    ) -> None:
        """Refresh target aliases from a directly assigned false-like constant.

        False or zero-valued constants establish aliases; assigning another name does not propagate its alias state.

        Args:
            targets: Assignment targets from which plain or destructured names are collected.
            value: Assigned expression; None or a value outside the false-constant check clears the names.
            aliases: Mutable alias set receiving or losing the collected target names.
        """
        assigned = {name for target in targets for name in _target_names(target)}
        if value is not None and is_false_constant(value):
            aliases.update(assigned)
            return
        aliases.difference_update(assigned)


def _ssl_verification_disabled_reason(
    target: str,
    call: ast.Call,
    false_aliases: set[str],
) -> tuple[str | None, str]:
    """Label recognized TLS-related call syntax using the current false aliases.

    Request calls accept a false-like literal or recorded alias; the other supported targets match by spelling alone.

    Args:
        target: Resolved call-target spelling to match against supported names.
        call: Call whose verification keyword is inspected for supported request methods.
        false_aliases: Names currently recorded from false-like assignments.

    Returns:
        Reason and source label for a match, or (None, an empty string) when no shape matches.
    """
    if target.startswith("requests."):
        last = target.split(".")[-1]
        if last in _REQUESTS_METHODS:
            verify = call_keyword(call, "verify")
            if verify is not None and is_false_constant(verify):
                return f"`{target}(verify=False)`", "literal-false"
            if isinstance(verify, ast.Name) and verify.id in false_aliases:
                return f"`{target}(verify={verify.id})`", "literal-false-origin"
    if target in {"ssl._create_unverified_context", "_create_unverified_context"}:
        return "`ssl._create_unverified_context()`", "unverified-context"
    if target in {"urllib3.disable_warnings", "disable_warnings"}:
        return "`urllib3.disable_warnings()`", "warning-suppression"
    return None, ""


@dataclass(frozen=True, slots=True)
class _SslFindingParts:
    """Values needed to render a disabled TLS verification finding."""

    unit: AnalysisUnit
    definition: RuleDefinition
    node: ast.Call
    target: str
    reason: str
    source_label: str


def _finding(parts: _SslFindingParts) -> Finding:
    """Build a TLS finding from the visitor's matched call details.

    Args:
        parts: Rule, unit, call location, target, reason, and source label collected for the match.

    Returns:
        Finding carrying the matched call span, TLS remediation, and derived metadata.
    """
    definition = parts.definition
    return Finding(
        rule_id=definition.id,
        message=f"{parts.reason} disables TLS certificate verification.",
        file_path=parts.unit.file.display_path,
        line=parts.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=parts.node.end_lineno,
        remediation=_TLS_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata=_finding_metadata(parts),
    )


def _finding_metadata(parts: _SslFindingParts) -> dict[str, str]:
    """Describe a TLS match for the finding metadata.

    Args:
        parts: Matched target and reason plus the rule and source label used for security metadata.

    Returns:
        New metadata dictionary containing the target, reason, and TLS source and sink classification.
    """
    return {
        "target": parts.target,
        "reason": parts.reason,
        **finding_security_metadata(
            parts.definition.id,
            source_label=parts.source_label,
            sink_label="tls-verification",
        ),
    }


def _target_names(target: ast.expr) -> set[str]:
    """Collect plain names from an assignment target or nested tuple or list.

    Args:
        target: Target expression to inspect recursively through tuple and list elements.

    Returns:
        Distinct bound names; an empty set for unsupported targets such as attributes.
    """
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Tuple | ast.List):
        return {name for item in target.elts for name in _target_names(item)}
    return set()


def _assigned_names(node: ast.AST) -> set[str]:
    """Collect bindings that invalidate aliases after a branching statement.

    Args:
        node: Statement subtree to inspect for stored names and nested definition bindings.

    Returns:
        Set of stored names and nested definition names, excluding bindings inside nested definition bodies.
    """
    collector = _AssignedNameCollector()
    collector.visit(node)
    return collector.names


class _AssignedNameCollector(ast.NodeVisitor):
    """Collect names assigned anywhere inside a statement subtree."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        """Record stored names.

        Args:
            node: Name node to inspect.
        """
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Record a nested function definition name without visiting its body.

        Args:
            node: Function definition to record.
        """
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Record a nested async function definition name without visiting its body.

        Args:
            node: Async function definition to record.
        """
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Record a nested class definition name without visiting its body.

        Args:
            node: Class definition to record.
        """
        self.names.add(node.name)
