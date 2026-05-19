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
    """Import alias map for normalizing references to ``yaml`` members."""

    aliases: dict[str, str]

    @classmethod
    def from_tree(cls, tree: ast.AST) -> "_YamlAliases":
        """Build YAML import aliases from a parsed module.

        Args:
            tree: Module AST to inspect for PyYAML imports.

        Returns:
            Alias map that resolves direct and aliased PyYAML references.
        """
        aliases: dict[str, str] = {"yaml": "yaml"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                _record_yaml_import_aliases(node, aliases)
            elif isinstance(node, ast.ImportFrom) and node.module == "yaml":
                _record_yaml_from_import_aliases(node, aliases)
        return cls(aliases)

    def normalize(self, target: str | None) -> str | None:
        """Normalize a call target through the collected YAML aliases.

        Args:
            target: Dotted call target, or None when the call is dynamic.

        Returns:
            Target rewritten to a ``yaml.*`` form when an alias is known.
        """
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
