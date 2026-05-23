"""``security.xxe`` - stdlib / lxml XML parsers vulnerable to external entities.

Catches calls to ``xml.etree.ElementTree.parse/fromstring/iterparse``,
``xml.sax.parse/parseString``, ``xml.dom.minidom.parse/parseString``,
``xml.dom.pulldom.parse/parseString``, and ``lxml.etree.parse/fromstring``.

Suppresses the entire file when ``defusedxml`` is imported - assumes the
developer is migrating to defusedxml's hardened parsers and that any
remaining stdlib calls are part of a transitional state.

Resolves the common import-alias shapes (``import xml.etree.ElementTree as
ET``, ``from xml.etree import ElementTree as ET``, ``from lxml import
etree``, ``from xml.etree.ElementTree import parse``) so the rule fires
regardless of how the module was imported.
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

_UNSAFE_XML_TARGETS: frozenset[str] = frozenset(
    {
        "xml.etree.ElementTree.parse",
        "xml.etree.ElementTree.fromstring",
        "xml.etree.ElementTree.iterparse",
        "xml.etree.ElementTree.XMLParser",
        "xml.sax.parse",
        "xml.sax.parseString",
        "xml.sax.make_parser",
        "xml.dom.minidom.parse",
        "xml.dom.minidom.parseString",
        "xml.dom.pulldom.parse",
        "xml.dom.pulldom.parseString",
        "lxml.etree.parse",
        "lxml.etree.fromstring",
    }
)
_SOURCE_NEEDLES: tuple[str, ...] = ("xml", "lxml", "etree", "minidom", "pulldom", "sax")
_REMEDIATION = (
    "Replace stdlib/lxml XML parsers with the corresponding `defusedxml` "
    "module (e.g. `from defusedxml.ElementTree import parse`). defusedxml "
    "disables external-entity resolution and DTD processing, blocking XXE, "
    "billion-laughs, and external-DTD attacks."
)
_XML_MODULE_PREFIXES: tuple[str, ...] = ("xml.", "lxml.")


class XxeRule(Rule):
    """Detect calls to XML parsers vulnerable to external entity expansion."""

    ID = "security.xxe"

    def definition(self) -> RuleDefinition:
        """Describe the XXE rule as a high-confidence ERROR.

        ERROR severity because XXE is a well-documented exfiltration and SSRF
        vector on un-hardened parsers; high confidence because the matched
        call targets exist only to parse XML and the defusedxml allowlist
        cleanly removes the migration false-positive class.

        Returns:
            Definition for the XXE rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="XML external entity (XXE)",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag calls to XXE-vulnerable XML parsers, allowlisting defusedxml files.

        Walks top-level imports to build an alias map (``ET`` →
        ``xml.etree.ElementTree``, ``etree`` → ``lxml.etree``, etc.) and
        normalises each call target through the map before checking it
        against the unsafe-target set. Any ``import defusedxml`` /
        ``from defusedxml`` in the file suppresses the rule for the whole
        file, on the assumption the migration is in progress.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unsafe XML parser call.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        if _has_defusedxml_import(unit.tree):
            return []
        definition = self.definition()
        aliases = _XmlAliases.from_tree(unit.tree)
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            target = aliases.normalize(call_target_name(node))
            if target not in _UNSAFE_XML_TARGETS:
                continue
            findings.append(_build_finding(definition, unit, node, target))
        return findings


def _has_defusedxml_import(tree: ast.AST) -> bool:
    if not isinstance(tree, ast.Module):
        return False
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "defusedxml" or alias.name.startswith("defusedxml."):
                    return True
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and (node.module == "defusedxml" or node.module.startswith("defusedxml."))
        ):
            return True
    return False


@dataclass(frozen=True, slots=True)
class _XmlAliases:
    """Maps local names to fully-qualified ``xml.*`` / ``lxml.*`` dotted paths."""

    aliases: dict[str, str]

    @classmethod
    def from_tree(cls, tree: ast.AST) -> "_XmlAliases":
        """Build an alias map from a module's top-level imports.

        Args:
            tree: Module AST to inspect for XML imports.

        Returns:
            Alias map keyed by local name with fully-qualified targets.
        """
        aliases: dict[str, str] = {}
        if not isinstance(tree, ast.Module):
            return cls(aliases)
        for node in tree.body:
            if isinstance(node, ast.Import):
                _record_import(node, aliases)
            elif isinstance(node, ast.ImportFrom):
                _record_from_import(node, aliases)
        return cls(aliases)

    def normalize(self, target: str | None) -> str | None:
        """Rewrite a call target through the collected aliases.

        Args:
            target: Dotted call target, or None when the call is dynamic.

        Returns:
            Fully-qualified target when the head matches a known alias,
            otherwise the input target unchanged.
        """
        if target is None:
            return None
        parts = target.split(".")
        head = parts[0]
        replacement = self.aliases.get(head)
        if replacement is None:
            return target
        return ".".join((replacement, *parts[1:]))


def _record_import(node: ast.Import, aliases: dict[str, str]) -> None:
    for alias in node.names:
        if not alias.name.startswith(_XML_MODULE_PREFIXES) and alias.name not in {"xml", "lxml"}:
            continue
        if alias.asname is not None:
            aliases[alias.asname] = alias.name


def _record_from_import(node: ast.ImportFrom, aliases: dict[str, str]) -> None:
    module = node.module
    if module is None:
        return
    if not module.startswith(_XML_MODULE_PREFIXES) and module not in {"xml", "lxml"}:
        return
    for alias in node.names:
        if alias.name == "*":
            continue
        local = alias.asname or alias.name
        aliases[local] = f"{module}.{alias.name}"


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    target: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"`{target}(...)` parses XML without external-entity protections - "
            "XXE / billion-laughs risk."
        ),
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
            "target": target,
            **finding_security_metadata(
                definition.id,
                source_label="xml-input",
                sink_label="xml-parser",
            ),
        },
    )
