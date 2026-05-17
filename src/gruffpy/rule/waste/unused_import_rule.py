"""Imports whose names are never referenced.

Skip:

- names listed in ``__all__`` (intentional re-exports);
- ``__init__.py`` modules (any name imported there is plausibly re-exported);
- imports tagged with ``# noqa`` on the import line.

Side-effect imports (``import sentry_sdk.init`` or ``import logging.config``)
are not yet detected — they typically come in as ``Import`` with multiple
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
    ID = "waste.unused-import"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Unused import",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        if Path(unit.file.display_path).name == "__init__.py":
            return []
        definition = self.definition()
        all_names = module_all_names(unit.tree)

        imports = _collect_imports(unit.tree)
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
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            continue
        if isinstance(node, ast.Name) and node.id in candidates:
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            root: ast.AST = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in candidates:
                used.add(root.id)
        if used == candidates:
            return used
    for annotation in _iter_annotation_nodes(tree):
        value = _string_annotation_value(annotation)
        if value is None:
            continue
        try:
            parsed = ast.parse(value, mode="eval")
        except SyntaxError:
            continue
        used.update(_collect_used_names(parsed, candidates))
        if used == candidates:
            return used
    return used


def _iter_annotation_nodes(tree: ast.AST) -> list[ast.AST]:
    annotations: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            annotations.append(node.annotation)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.returns is not None:
            annotations.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            annotations.append(node.annotation)
    return annotations


def _string_annotation_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _has_noqa(source_lines: list[str], lineno: int) -> bool:
    if lineno < 1 or lineno > len(source_lines):
        return False
    return "# noqa" in source_lines[lineno - 1].lower()
