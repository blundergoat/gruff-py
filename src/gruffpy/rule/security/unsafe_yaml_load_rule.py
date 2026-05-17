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
    ID = "security.unsafe-yaml-load"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Unsafe YAML load",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
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
    aliases: dict[str, str]

    @classmethod
    def from_tree(cls, tree: ast.AST) -> "_YamlAliases":
        aliases: dict[str, str] = {"yaml": "yaml"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                _record_yaml_import_aliases(node, aliases)
            elif isinstance(node, ast.ImportFrom) and node.module == "yaml":
                _record_yaml_from_import_aliases(node, aliases)
        return cls(aliases)

    def normalize(self, target: str | None) -> str | None:
        if target is None:
            return None
        parts = target.split(".")
        replacement = self.aliases.get(parts[0])
        if replacement is None:
            return target
        return ".".join((replacement, *parts[1:]))


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


def _is_unsafe_yaml_call(
    call: ast.Call,
    target: str | None,
    aliases: _YamlAliases,
) -> bool:
    if target == "yaml.unsafe_load":
        return True
    if target != "yaml.load":
        return False
    loader = call_keyword(call, "Loader")
    if loader is None:
        return True
    loader_target = aliases.normalize(call_target_name_from_expr(loader))
    if loader_target in _SAFE_LOADERS:
        return False
    return loader_target in _UNSAFE_LOADERS


def call_target_name_from_expr(node: ast.expr) -> str | None:
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
