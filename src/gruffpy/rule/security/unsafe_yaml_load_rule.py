"""``security.unsafe-yaml-load`` — PyYAML loaders that can construct objects."""

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
from gruffpy.rule.security._security_node_helper import call_keyword, call_target_name

_UNSAFE_LOADERS: frozenset[str] = frozenset(
    {
        "yaml.Loader",
        "yaml.UnsafeLoader",
        "yaml.CLoader",
        "yaml.CUnsafeLoader",
    }
)
_SAFE_LOADERS: frozenset[str] = frozenset({"yaml.SafeLoader", "yaml.CSafeLoader"})


class UnsafeYamlLoadRule(Rule):
    """Find PyYAML calls that can construct arbitrary Python objects."""

    ID = "security.unsafe-yaml-load"

    def definition(self) -> RuleDefinition:
        """Describe the unsafe-yaml-load rule as a high-confidence ERROR.

        ERROR severity because ``yaml.load`` without an explicit safe Loader
        constructs arbitrary Python objects from input — a well-known RCE
        vector. High confidence because the rule matches both the explicit
        ``yaml.unsafe_load`` call and the bare ``yaml.load(...)`` form,
        respecting import aliases.

        Returns:
            Definition for the unsafe-yaml-load rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unsafe YAML load",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``yaml.unsafe_load`` and ``yaml.load`` without a safe Loader.

        Resolves ``import yaml as y`` / ``from yaml import load`` aliases so
        the rule fires regardless of how PyYAML was imported. ``yaml.load``
        is safe only when ``Loader=`` is explicitly ``SafeLoader`` /
        ``CSafeLoader``; ``Loader=Loader/UnsafeLoader/CLoader/CUnsafeLoader``
        or a missing ``Loader=`` is flagged.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per unsafe ``yaml.load`` / ``yaml.unsafe_load`` call.
        """
        if unit.tree is None or "yaml" not in unit.source:
            return []
        definition = self.definition()
        aliases = _YamlAliases.from_tree(unit.tree)
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            target = aliases.normalize(call_target_name(node))
            if not _is_unsafe_yaml_call(node, target, aliases):
                continue
            findings.append(_finding(definition, unit, node, target or "yaml.load"))
        return findings


@dataclass(frozen=True, slots=True)
class _YamlAliases:
    """Resolves PyYAML names through imports and module-level loader assignments.

    Imports are order-independent (hoisted by Python at module load).
    Module-level loader assignments are tracked with their source lineno so
    a call only sees assignments that appear lexically before it; this
    prevents a later ``loader = yaml.SafeLoader`` from masking an earlier
    ``yaml.load(..., Loader=loader)`` and also avoids leaking function-local
    aliases out of their defining scope.
    """

    imports: dict[str, str]
    loader_assignments: tuple[tuple[int, str, str], ...]

    @classmethod
    def from_tree(cls, tree: ast.AST) -> "_YamlAliases":
        """Build YAML imports and module-level loader assignments.

        Args:
            tree: Module AST to inspect for PyYAML usage.

        Returns:
            Resolver wrapping imports plus ordered loader assignments.
        """
        collector = _AliasCollector()
        collector.visit(tree)
        return cls(collector.imports, tuple(collector.loader_assignments))

    def normalize(self, target: str | None) -> str | None:
        """Rewrite *target* through known PyYAML import aliases.

        Used for call targets like ``yaml.load``; ignores loader assignments
        which require lexical-order resolution via :meth:`resolve_loader`.

        Args:
            target: Dotted call target, or None when the call is dynamic.

        Returns:
            Target rewritten to a ``yaml.*`` form when an alias is known.
        """
        if target is None:
            return None
        parts = target.split(".")
        replacement = self.imports.get(parts[0])
        if replacement is None:
            return target
        return ".".join((replacement, *parts[1:]))

    def resolve_loader(self, target: str | None, call_lineno: int) -> str | None:
        """Resolve a loader-argument name at a call site.

        Args:
            target: Dotted loader expression at the call site.
            call_lineno: Source line of the enclosing call; assignments at
                or after this line are not visible to the call.

        Returns:
            Normalized loader target, or *target* when no alias applies.
        """
        normalized = self.normalize(target)
        if normalized != target:
            return normalized
        if target is None or "." in target:
            return normalized
        latest: str | None = None
        for lineno, name, value in self.loader_assignments:
            if name == target and lineno < call_lineno:
                latest = value
        return latest if latest is not None else normalized


class _AliasCollector(ast.NodeVisitor):
    """Collects PyYAML imports plus module-level loader assignments."""

    def __init__(self) -> None:
        self.imports: dict[str, str] = {"yaml": "yaml"}
        self.loader_assignments: list[tuple[int, str, str]] = []
        self._scope_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_Import(self, node: ast.Import) -> None:
        _record_yaml_import_aliases(node, self.imports)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "yaml":
            _record_yaml_from_import_aliases(node, self.imports)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._scope_depth == 0:
            _record_yaml_loader_assignments(
                node.targets, node.value, self.imports, self.loader_assignments, node.lineno
            )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if self._scope_depth == 0:
            _record_yaml_loader_assignments(
                [node.target], node.value, self.imports, self.loader_assignments, node.lineno
            )
        self.generic_visit(node)


def _record_yaml_import_aliases(node: ast.Import, aliases: dict[str, str]) -> None:
    for alias in node.names:
        if alias.name != "yaml":
            continue
        aliases[alias.asname or "yaml"] = "yaml"


def _record_yaml_from_import_aliases(node: ast.ImportFrom, aliases: dict[str, str]) -> None:
    for alias in node.names:
        if alias.name == "*":
            continue
        aliases[alias.asname or alias.name] = f"yaml.{alias.name}"


def _record_yaml_loader_assignments(
    targets: list[ast.expr],
    value: ast.expr | None,
    imports: dict[str, str],
    loader_assignments: list[tuple[int, str, str]],
    lineno: int,
) -> None:
    if value is None:
        return
    loader_target = _normalize_with_imports(call_target_name_from_expr(value), imports)
    if loader_target not in _SAFE_LOADERS and loader_target not in _UNSAFE_LOADERS:
        return
    for target in targets:
        if isinstance(target, ast.Name):
            loader_assignments.append((lineno, target.id, loader_target))


def _is_unsafe_yaml_call(
    call: ast.Call,
    target: str | None,
    aliases: _YamlAliases,
) -> bool:
    if target == "yaml.unsafe_load":
        return True
    if target != "yaml.load":
        return False
    loader = _loader_argument(call)
    if loader is None:
        return True
    loader_target = aliases.resolve_loader(call_target_name_from_expr(loader), call.lineno)
    return loader_target not in _SAFE_LOADERS


def _normalize_with_imports(target: str | None, imports: dict[str, str]) -> str | None:
    if target is None:
        return None
    parts = target.split(".")
    replacement = imports.get(parts[0])
    if replacement is None:
        return target
    return ".".join((replacement, *parts[1:]))


def _loader_argument(call: ast.Call) -> ast.expr | None:
    keyword_loader = call_keyword(call, "Loader")
    if keyword_loader is not None:
        return keyword_loader
    if len(call.args) >= 2:
        return call.args[1]
    return None


def call_target_name_from_expr(node: ast.expr) -> str | None:
    """Return a dotted target name from a name or attribute expression.

    Args:
        node: Expression to convert into a dotted name.

    Returns:
        Dotted target name, or None when the expression is not static.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = call_target_name_from_expr(node.value)
        if prefix is None:
            return None
        return f"{prefix}.{node.attr}"
    return None


def _finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    target: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=f"`{target}(...)` can construct arbitrary Python objects from YAML input.",
        file_path=unit.file.display_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation="Use ``yaml.safe_load`` or pass ``Loader=yaml.SafeLoader`` for untrusted YAML.",
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "target": target,
            **finding_security_metadata(
                definition.id,
                source_label="yaml-input",
                sink_label="unsafe-yaml-loader",
            ),
        },
    )
