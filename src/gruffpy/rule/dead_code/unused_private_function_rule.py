"""Find private functions or methods with no proved caller in the scan.

Project scans combine each file's local references with later loads through
resolved imports, so users do not receive deletion advice for registered
callbacks visible elsewhere. Narrow scans omit module-level conclusions while
retaining class-local method checks and the existing dynamic allowlist.
"""

import ast
import re
from collections import Counter
from collections.abc import Container
from dataclasses import dataclass

from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    has_framework_base,
    has_framework_decorator,
    is_abstract_method,
    is_overload_stub,
    is_protocol_method_stub,
    module_all_names,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.private_function_liveness import (
    ExternalReferenceCoverage,
    PrivateFunctionKey,
    PrivateFunctionLiveness,
    build_private_function_liveness,
)
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
_PRIVATE_DEF_RE = re.compile(r"\bdef\s+_")


@dataclass(frozen=True, slots=True)
class _PrivateFunctionCandidate:
    """Carry one private definition through local and project evidence checks.

    Module-level candidates may use external import-load evidence. Methods and
    nested functions keep their existing enclosing-scope analysis.
    """

    node: FunctionNode
    parents: list[ast.AST]
    scope: ast.AST
    is_module_level: bool


@dataclass(frozen=True, slots=True)
class _ReferenceCounts:
    """Count static references visible in one user source scope.

    The rule compares enclosing and defining scopes so a function's own name or
    body does not accidentally prove that another caller exists.
    """

    names: Counter[str]
    attributes: Counter[str]
    getattr_names: Counter[str]
    getattr_prefixes: Counter[str]


class UnusedPrivateFunctionRule(Rule):
    """Show deletion advice only when scanned static evidence proves no caller.

    Registry users reach project dispatch, which handles full versus partial
    scope and cross-module imports. Direct per-file analysis remains available
    for local rule tests and preserves the pre-project behavior.
    """

    ID = "dead-code.unused-private-function"

    def definition(self) -> RuleDefinition:
        """Describe the unused-private-function rule as a medium-confidence warning.

        Medium confidence: ``getattr``, plugin registries, and other
        metaprogramming patterns can call a private function in ways static
        analysis can't see.

        Returns:
            Definition for the unused-private-function rule under the
            dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unused private function",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Run the legacy local check used by focused rule-level journeys.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the allowlist.

        Returns:
            One finding per unreferenced private function or method.
        """
        return _analyse_unit(
            unit,
            context,
            definition=self.definition(),
            include_module_level=True,
            project_liveness=None,
        )

    def analyse_project(
        self,
        units: list[AnalysisUnit],
        context: RuleContext,
    ) -> list[Finding]:
        """Combine local checks with external import loads for the user's scan.

        Args:
            units: Parsed Python files selected for the current analysis journey.
            context: Run configuration and full/partial scan classification.

        Returns:
            Ordered candidate findings; module-level rows are absent on partial scans.
        """
        parsed_units: list[AnalysisUnit] = []
        # Only parsed Python modules can contribute candidates or import evidence.
        for unit in units:
            # A parse failure has no trustworthy private-definition structure.
            if not isinstance(unit.tree, ast.Module):
                continue
            parsed_units.append(unit)

        # Full-project discovery is required before absence can support deletion advice.
        include_module_level = context.scan_scope == "full-project"
        project_liveness: PrivateFunctionLiveness | None = None
        # Complete scans build external evidence once before checking each producer.
        if include_module_level:
            candidate_keys = _module_private_candidate_keys(parsed_units)
            project_liveness = build_private_function_liveness(parsed_units, candidate_keys)

        definition = self.definition()
        findings: list[Finding] = []
        # Each scanned file keeps its existing class-local and allowlist checks.
        for unit in parsed_units:
            findings.extend(
                _analyse_unit(
                    unit,
                    context,
                    definition=definition,
                    include_module_level=include_module_level,
                    project_liveness=project_liveness,
                )
            )
        return findings


def _module_private_candidate_keys(
    units: list[AnalysisUnit],
) -> frozenset[PrivateFunctionKey]:
    """Collect importable top-level private functions from scanned user files.

    Args:
        units: Parsed Python modules from a complete project scan; empty is valid.

    Returns:
        Producer path/name keys eligible for cross-module liveness evidence.
    """
    candidate_keys: set[PrivateFunctionKey] = set()
    # Direct module-body definitions are the functions another module can import.
    for unit in units:
        tree = unit.tree
        # Parsed-unit filtering normally guarantees a module; keep direct calls safe.
        if not isinstance(tree, ast.Module):
            continue
        # A class or nested function is not importable as ``module._name``.
        for node in tree.body:
            # Public, dunder, and non-function declarations cannot become candidates.
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # The local rule applies the remaining framework and export exemptions.
            if not _is_private(node.name) or _is_dunder(node.name):
                continue
            candidate_keys.add((unit.file.display_path, node.name))
    return frozenset(candidate_keys)


def _analyse_unit(
    unit: AnalysisUnit,
    context: RuleContext,
    *,
    definition: RuleDefinition,
    include_module_level: bool,
    project_liveness: PrivateFunctionLiveness | None,
) -> list[Finding]:
    """Apply local evidence and optional project liveness to one scanned file.

    Args:
        unit: Parsed source file being reviewed; parse failures return no finding.
        context: Rule execution context supplying the dynamic allowlist.
        definition: Metadata from the active rule instance.
        include_module_level: False when the user's scan cannot see all callers.
        project_liveness: Full-scan import evidence, or None for local/partial checks.

    Returns:
        Findings safe to show for this file and the user's selected scan scope.
    """
    # Files without a private definition token avoid an unnecessary AST walk.
    if unit.tree is None or not _PRIVATE_DEF_RE.search(unit.source):
        return []
    all_names = module_all_names(unit.tree)
    allowlist = context.config.dead_code_allowlist

    findings: list[Finding] = []
    scope_references: dict[int, _ReferenceCounts] = {}
    # Every candidate keeps the existing module/class reference and exemption model.
    for raw_node in ast.walk(unit.tree):
        candidate = _private_function_candidate(raw_node, unit.tree, all_names)
        # Non-private declarations and built-in dynamic exemptions produce no advice.
        if candidate is None:
            continue
        # A narrow scan cannot prove that an importable module function has no caller.
        if candidate.is_module_level and not include_module_level:
            continue
        scope_key = id(candidate.scope)
        references = scope_references.get(scope_key)
        # Each enclosing module/class is counted once regardless of candidate count.
        if references is None:
            references = _collect_references(candidate.scope)
            scope_references[scope_key] = references
        own_references = _collect_references(candidate.node)
        # A local call or static getattr already proves the user's function is live.
        if _has_external_reference(candidate.node.name, references, own_references):
            continue
        # One uniquely resolved external load also proves a top-level function is live.
        if (
            candidate.is_module_level
            and project_liveness is not None
            and project_liveness.is_live(unit.file.display_path, candidate.node.name)
        ):
            continue
        # Framework/plugin cases the static model cannot prove stay on ADR-015 allowlists.
        if _is_allowlisted(unit, candidate, allowlist):
            continue
        coverage: ExternalReferenceCoverage | None = None
        # Only full-project module findings disclose external-reference completeness.
        if candidate.is_module_level and project_liveness is not None:
            coverage = project_liveness.coverage_for(
                unit.file.display_path,
                candidate.node.name,
            )
        findings.append(
            _unused_private_function_finding(
                unit,
                definition,
                candidate,
                coverage,
            )
        )
    return findings


def _is_allowlisted(
    unit: AnalysisUnit,
    candidate: "_PrivateFunctionCandidate",
    allowlist: DeadCodeAllowlist,
) -> bool:
    if allowlist.matches_path(unit.file.display_path):
        return True
    symbol = qualified_symbol(candidate.node, candidate.parents)
    if allowlist.matches_symbol(symbol):
        return True
    return allowlist.matches_decorator(_decorator_names(candidate.node.decorator_list))


def _decorator_names(decorators: list[ast.expr]) -> tuple[str, ...]:
    names: list[str] = []
    for decorator in decorators:
        full = _decorator_repr(decorator)
        if not full:
            continue
        names.append(full)
        bare = full.rsplit(".", 1)[-1]
        if bare and bare != full:
            names.append(bare)
    return tuple(names)


def _decorator_repr(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _decorator_repr(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        prefix = _decorator_repr(decorator.value)
        return f"{prefix}.{decorator.attr}" if prefix else decorator.attr
    return ""


def _private_function_candidate(
    node: ast.AST,
    tree: ast.AST,
    all_names: Container[str],
) -> _PrivateFunctionCandidate | None:
    """Return one definition eligible for local and project evidence checks.

    Args:
        node: Parsed declaration candidate; non-functions return None.
        tree: User module that owns top-level candidates; never None.
        all_names: Explicit exports that users intend other modules to import.

    Returns:
        Candidate with its scan scope, or None when no finding can apply.
    """
    # Non-function nodes cannot produce private-function advice for the user.
    if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return None

    parents = parent_chain(node)
    # The nearest class makes this a class-local method rather than a module import.
    parent_cls = next((p for p in reversed(parents) if isinstance(p, ast.ClassDef)), None)
    # Dunder, export, protocol, framework, and public shapes remain exempt.
    if _should_skip_private_function(node, parents, parent_cls, all_names):
        return None

    # Liveness belongs to the nearest lexical owner, not every method in an outer class.
    scope = next(
        (
            parent
            for parent in reversed(parents)
            if isinstance(
                parent,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
            )
        ),
        tree,
    )

    return _PrivateFunctionCandidate(
        node=node,
        parents=parents,
        scope=scope,
        is_module_level=scope is tree,
    )


def _should_skip_private_function(
    node: FunctionNode,
    parents: list[ast.AST],
    parent_cls: ast.ClassDef | None,
    all_names: Container[str],
) -> bool:
    return (
        not _is_private(node.name)
        or _is_dunder(node.name)
        or node.name in all_names
        or is_abstract_method(node)
        or is_overload_stub(node)
        or has_framework_decorator(node)
        or is_protocol_method_stub(node, parents)
        or (parent_cls is not None and has_framework_base(parent_cls))
    )


def _unused_private_function_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _PrivateFunctionCandidate,
    coverage: ExternalReferenceCoverage | None = None,
) -> Finding:
    """Build the deletion advice shown after local and project checks finish.

    Args:
        unit: User file displayed as the finding location; never None.
        definition: Stable public rule details used in every output format.
        candidate: Private definition with no proved caller in the current scan.
        coverage: Project evidence quality, or None for class-local/local analysis.

    Returns:
        One finding whose identity stays stable as coverage metadata is added.
    """
    symbol = qualified_symbol(candidate.node, candidate.parents)
    metadata: dict[str, object] = {"name": candidate.node.name}
    confidence = definition.confidence
    # Full-project module findings tell users whether duplicate paths limited proof.
    if coverage is not None:
        metadata.update(
            {
                "scanScope": "full-project",
                "externalReferenceCoverage": coverage,
            }
        )
        # A loaded ambiguous import cannot prove which duplicate module owns the call.
        if coverage == "ambiguous":
            confidence = Confidence.LOW
    return Finding(
        rule_id=definition.id,
        message=(f"Private function {symbol!r} is never called in its enclosing scope."),
        file_path=unit.file.display_path,
        line=candidate.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=confidence,
        end_line=candidate.node.end_lineno,
        symbol=symbol,
        remediation=(
            "Delete the function or add a real caller. If a framework or plugin loads it "
            "dynamically, keep the underscore and add the documented dead-code allowlist."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata=metadata,
    )


def _is_private(name: str) -> bool:
    return name.startswith("_")


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__") and len(name) > 4


def _collect_references(root: ast.AST) -> _ReferenceCounts:
    references = _ReferenceCounts(
        names=Counter(),
        attributes=Counter(),
        getattr_names=Counter(),
        getattr_prefixes=Counter(),
    )
    for node in ast.walk(root):
        if isinstance(node, ast.Name):
            references.names[node.id] += 1
        elif isinstance(node, ast.Attribute):
            references.attributes[node.attr] += 1
        elif isinstance(node, ast.Call):
            _collect_getattr_reference(node, references)
    return references


def _collect_getattr_reference(node: ast.Call, references: _ReferenceCounts) -> None:
    if not isinstance(node.func, ast.Name) or node.func.id != "getattr":
        return
    if len(node.args) < 2:
        return
    name_arg = node.args[1]
    if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
        references.getattr_names[name_arg.value] += 1
        return
    if isinstance(name_arg, ast.JoinedStr):
        prefix = _joined_string_static_prefix(name_arg)
        if len(prefix) >= 3:
            references.getattr_prefixes[prefix] += 1


def _has_external_reference(
    name: str,
    scope: _ReferenceCounts,
    defining_node: _ReferenceCounts,
) -> bool:
    if scope.names[name] > defining_node.names[name]:
        return True
    if scope.attributes[name] > defining_node.attributes[name]:
        return True
    if scope.getattr_names[name] > defining_node.getattr_names[name]:
        return True
    return any(
        name.startswith(prefix) and count > defining_node.getattr_prefixes[prefix]
        for prefix, count in scope.getattr_prefixes.items()
    )


def _joined_string_static_prefix(value: ast.JoinedStr) -> str:
    prefix_parts: list[str] = []
    for part in value.values:
        if isinstance(part, ast.FormattedValue):
            break
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            prefix_parts.append(part.value)
    return "".join(prefix_parts)
