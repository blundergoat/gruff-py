"""Imports whose names are never referenced.

Skip:

- names listed in ``__all__`` (intentional re-exports);
- ``__init__.py`` modules (any name imported there is plausibly re-exported);
- imports tagged with ``# noqa`` on the import line;
- ``from __future__ import …`` directives - these are compile-time
  PEP 236 / 563 markers whose name never appears in the runtime
  namespace, so the "is it referenced?" question doesn't apply.

Side-effect imports (``import sentry_sdk.init`` or ``import logging.config``)
are not yet detected - they typically come in as ``Import`` with multiple
dotted names; v0.1 flags only the simple-name case.
"""

import ast
from pathlib import Path

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import module_all_names
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule


class UnusedImportRule(Rule):
    """Detect imported names never referenced in their declaring module."""

    ID = "waste.unused-import"

    def definition(self) -> RuleDefinition:
        """Describe the unused-import rule as a high-confidence dead-code warning.

        High confidence because the rule honours ``__all__`` re-exports,
        skips ``__init__.py`` modules, and parses string annotations
        (forward references) - the remaining false-positive surface is
        side-effect-only imports (``import logging.config``) which the v0.1
        scope intentionally doesn't cover.

        Returns:
            Definition tagging this rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unused import",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag imports whose locally-bound name is never referenced.

        Skips ``__init__.py`` modules wholesale, honours ``__all__`` re-exports,
        and respects ``# noqa`` on the import line.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unused import alias, located at the alias's line.
        """
        if unit.tree is None:
            return []
        if Path(unit.file.display_path).name == "__init__.py":
            return []
        imports = _collect_imports(unit.tree)
        if not imports:
            return []

        definition = self.definition()
        all_names = module_all_names(unit.tree)
        used_names = _collect_used_names(unit.tree, set(imports))

        source_lines = unit.source.splitlines() if unit.source else []
        findings: list[Finding] = []
        for name, alias_node in imports.items():
            if name in used_names or name in all_names:
                continue
            if _has_noqa(source_lines, alias_node.lineno):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Import {name!r} is never referenced.",
                    file_path=unit.file.display_path,
                    line=alias_node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=alias_node.end_lineno,
                    remediation="Remove the import or add it to `__all__`.",
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"name": name},
                ),
            )
        return findings


def _collect_imports(tree: ast.AST) -> dict[str, ast.alias]:
    """Return a mapping of locally-bound name -> alias node.

    ``import a.b.c`` binds ``a`` locally. ``from x import y as z`` binds ``z``.
    The alias node is preserved so we can report its line.
    """
    imports: dict[str, ast.alias] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                imports[local] = alias
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                # PEP 236/563 directives - compile-time only, no runtime name to reference.
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                imports[local] = alias
    return imports


def _collect_used_names(tree: ast.AST, candidates: set[str]) -> set[str]:
    """Return the subset of *candidates* that appear as Name/Attribute roots
    anywhere in *tree* outside of import statements themselves."""
    used: set[str] = set()
    string_annotations: list[str] = []
    for node in ast.walk(tree):
        name = _candidate_use_name(node)
        if name is not None and name in candidates:
            used.add(name)
            if used == candidates:
                return used
        string_annotations.extend(_string_annotation_values(node))

    if used == candidates:
        return used
    _collect_string_annotation_used_names(string_annotations, candidates, used)
    return used


def _candidate_use_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Import | ast.ImportFrom):
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _attribute_root_name(node)
    return None


def _attribute_root_name(node: ast.Attribute) -> str | None:
    root: ast.AST = node
    while isinstance(root, ast.Attribute):
        root = root.value
    if isinstance(root, ast.Name):
        return root.id
    return None


def _collect_string_annotation_used_names(
    annotation_values: list[str],
    candidates: set[str],
    used: set[str],
) -> None:
    for value in annotation_values:
        try:
            parsed = ast.parse(value, mode="eval")
        except SyntaxError:
            continue
        used.update(_collect_used_names(parsed, candidates))
        if used == candidates:
            return


def _string_annotation_values(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.arg) and node.annotation is not None:
        value = _string_annotation_value(node.annotation)
        return (value,) if value is not None else ()
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.returns is not None:
        value = _string_annotation_value(node.returns)
        return (value,) if value is not None else ()
    if isinstance(node, ast.AnnAssign):
        value = _string_annotation_value(node.annotation)
        return (value,) if value is not None else ()
    return ()


def _string_annotation_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _has_noqa(source_lines: list[str], lineno: int) -> bool:
    if lineno < 1 or lineno > len(source_lines):
        return False
    return "# noqa" in source_lines[lineno - 1].lower()
