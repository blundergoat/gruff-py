"""``security.paramiko-no-host-key-check`` - SSH connections that accept any host key.

``paramiko.AutoAddPolicy()`` and ``paramiko.WarningPolicy()`` cause an SSH
client to accept (or merely log) unknown host keys. Both bypass the central
defence against man-in-the-middle attacks on SSH: pinned, verified host
keys. The safe alternative is ``paramiko.RejectPolicy()`` combined with an
explicit ``load_host_keys`` / ``load_system_host_keys`` populated trust
store.

Match shapes (paramiko import required in the file):

- ``paramiko.AutoAddPolicy()``, ``paramiko.WarningPolicy()``
- ``AutoAddPolicy()``, ``WarningPolicy()`` (after ``from paramiko import``)

Aliased imports such as ``import paramiko as p`` are resolved.
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
from gruffpy.rule.security._security_node_helper import call_target_name

_UNSAFE_POLICY_LEAVES: frozenset[str] = frozenset({"AutoAddPolicy", "WarningPolicy"})
_SOURCE_NEEDLES: tuple[str, ...] = ("paramiko",)
_REMEDIATION = (
    "Use `paramiko.RejectPolicy()` and populate the client's host-key store "
    "explicitly (`client.load_host_keys(path)` or `load_system_host_keys()`). "
    "Auto-adding host keys defeats SSH's MITM protection."
)


class ParamikoNoHostKeyCheckRule(Rule):
    """Detect paramiko SSH clients that auto-add or only warn on unknown host keys."""

    ID = "security.paramiko-no-host-key-check"

    def definition(self) -> RuleDefinition:
        """Describe the paramiko host-key rule as a high-confidence ERROR.

        ERROR severity because the unsafe policies remove the only thing
        stopping an SSH MITM attack; high confidence because the matched
        class names are unambiguous paramiko-defined policy types.

        Returns:
            Definition for the paramiko host-key rule under the security
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Paramiko accepts unknown host keys",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag instantiation of paramiko AutoAddPolicy / WarningPolicy.

        File-level gate: must import paramiko (the policy class names are
        common-looking enough that an unrelated library could share them).
        Resolves ``import paramiko as p`` and ``from paramiko import
        AutoAddPolicy as X`` aliases.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per AutoAddPolicy / WarningPolicy instantiation.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        aliases = _ParamikoAliases.from_tree(unit.tree)
        if not aliases.is_paramiko_imported:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            leaf = _unsafe_policy_leaf(node, aliases)
            if leaf is None:
                continue
            findings.append(_build_finding(definition, unit, node, leaf))
        return findings


@dataclass(frozen=True, slots=True)
class _ParamikoAliases:
    """Tracks paramiko's module alias and any bare-named imported policy classes."""

    is_paramiko_imported: bool
    module_aliases: frozenset[str]
    bare_unsafe_names: dict[str, str]

    @classmethod
    def from_tree(cls, tree: ast.AST) -> "_ParamikoAliases":
        """Build the alias map from a module's top-level imports.

        Args:
            tree: Module AST to inspect.

        Returns:
            Alias record capturing paramiko's local module names and any
            policy classes imported directly into the module namespace.
        """
        if not isinstance(tree, ast.Module):
            return cls(False, frozenset(), {})
        module_aliases: set[str] = set()
        bare_unsafe: dict[str, str] = {}
        imported = False
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "paramiko":
                        imported = True
                        module_aliases.add(alias.asname or "paramiko")
            elif isinstance(node, ast.ImportFrom) and node.module == "paramiko":
                imported = True
                for alias in node.names:
                    if alias.name in _UNSAFE_POLICY_LEAVES:
                        bare_unsafe[alias.asname or alias.name] = alias.name
        return cls(imported, frozenset(module_aliases), bare_unsafe)


def _unsafe_policy_leaf(call: ast.Call, aliases: _ParamikoAliases) -> str | None:
    target = call_target_name(call)
    if target is None:
        return None
    parts = target.split(".")
    if len(parts) == 1:
        return aliases.bare_unsafe_names.get(parts[0])
    if parts[0] in aliases.module_aliases and parts[-1] in _UNSAFE_POLICY_LEAVES:
        return parts[-1]
    return None


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    leaf: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=f"`paramiko.{leaf}()` accepts unknown SSH host keys - MITM risk.",
        file_path=unit.file.display_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "policy": leaf,
            **finding_security_metadata(
                definition.id,
                source_label="ssh-handshake",
                sink_label="ssh-host-key-policy",
            ),
        },
    )
