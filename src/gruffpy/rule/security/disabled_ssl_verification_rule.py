"""``security.disabled-ssl-verification`` — explicit SSL/TLS verify disablement.

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

_REQUESTS_METHODS: frozenset[str] = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "request"}
)
_TLS_REMEDIATION = (
    "Use a properly verified TLS context. If you need a custom trust "
    "store, configure CA bundles instead of disabling verification."
)


class DisabledSslVerificationRule(Rule):
    ID = "security.disabled-ssl-verification"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Disabled SSL verification",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        visitor = _DisabledSslVerificationVisitor(unit, definition)
        visitor.visit(unit.tree)
        return visitor.findings


class _DisabledSslVerificationVisitor(ast.NodeVisitor):
    def __init__(self, unit: AnalysisUnit, definition: RuleDefinition) -> None:
        self._unit = unit
        self._definition = definition
        self._false_aliases: set[str] = set()
        self.findings: list[Finding] = []

    def visit_Module(self, node: ast.Module) -> None:
        self._visit_scope_body(node.body, false_aliases=set())

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scope_body(node.body, false_aliases=set())

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scope_body(node.body, false_aliases=set())

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scope_body(node.body, false_aliases=set())

    def visit_Call(self, node: ast.Call) -> None:
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
        aliases = set(false_aliases)
        for stmt in body:
            self._visit_scope_statement(stmt, aliases)

    def _visit_scope_statement(self, stmt: ast.stmt, aliases: set[str]) -> None:
        if self._did_visit_definition_or_assignment(stmt, aliases):
            return
        if self._did_visit_conditional_or_branching_statement(stmt, aliases):
            return
        self._visit_with_aliases(stmt, aliases)

    def _did_visit_definition_or_assignment(self, stmt: ast.stmt, aliases: set[str]) -> bool:
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
        aliases.discard(stmt.name)
        self.visit(stmt)

    def _visit_assignment(self, stmt: ast.Assign, aliases: set[str]) -> None:
        self._visit_with_aliases(stmt.value, aliases)
        self._record_assignment(stmt.targets, stmt.value, aliases)

    def _visit_annotated_assignment(self, stmt: ast.AnnAssign, aliases: set[str]) -> None:
        if stmt.value is not None:
            self._visit_with_aliases(stmt.value, aliases)
        self._record_assignment([stmt.target], stmt.value, aliases)

    def _visit_augmented_assignment(self, stmt: ast.AugAssign, aliases: set[str]) -> None:
        self._visit_with_aliases(stmt.value, aliases)
        aliases.difference_update(_target_names(stmt.target))

    def _visit_if_statement(self, stmt: ast.If, aliases: set[str]) -> None:
        self._visit_with_aliases(stmt.test, aliases)
        self._visit_scope_body(stmt.body, set(aliases))
        self._visit_scope_body(stmt.orelse, set(aliases))
        aliases.difference_update(_assigned_names(stmt))

    def _visit_branching_scope_statement(self, stmt: ast.stmt, aliases: set[str]) -> None:
        self._visit_branching_statement(stmt, aliases)
        aliases.difference_update(_assigned_names(stmt))

    def _visit_branching_statement(self, stmt: ast.stmt, aliases: set[str]) -> None:
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
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Tuple | ast.List):
        return {name for item in target.elts for name in _target_names(item)}
    return set()


def _assigned_names(node: ast.AST) -> set[str]:
    collector = _AssignedNameCollector()
    collector.visit(node)
    return collector.names


class _AssignedNameCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)
