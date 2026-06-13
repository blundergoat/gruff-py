"""``security.unsanitized-markdown-interpolation`` - raw values inside markdown link shapes.

Detects f-strings and ``str.format`` calls that build the markdown link shape
``[label](url)`` with a dynamic label or url that is not wrapped in any call.
A label value of ``evil](https://bad.example) trick`` turns
``[{label}]({real_url})`` into markdown whose *first* parsed link is the
injected pair, redirecting the rendered link target. The analyzer cannot know
which function sanitises, so the presence of some transformation - any call
wrapping the interpolated expression - is the proxy for "this site remembered
the sanitiser"; bare names, attributes, and subscripts fire.

Concatenation chains (``"[" + a + "](" + b + ")"``) are a documented gap in
this version.
"""

import ast
import re

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

_PLACEHOLDER = "\x00"
_LINK_PATTERN = re.compile(r"\[([^\[\]]*)\]\(([^()]*)\)")
_FORMAT_FIELD_PATTERN = re.compile(r"\{([^{}:!]*)(?:[:!][^{}]*)?\}")
_REMEDIATION = (
    "Escape the interpolated value before it enters the link shape: strip or "
    "percent-encode `]`, `(`, and `)` in labels and urls (a markdown_label()/"
    "markdown_url() helper), then interpolate the escaped value."
)


class UnsanitizedMarkdownInterpolationRule(Rule):
    """Detect markdown [label](url) shapes interpolating unwrapped dynamic values."""

    ID = "security.unsanitized-markdown-interpolation"

    def definition(self) -> RuleDefinition:
        """Describe the unsanitized-markdown-interpolation rule as a medium-confidence advisory.

        Medium confidence: any wrapping call is accepted as the sanitiser
        proxy, so the rule cannot distinguish escaping calls from unrelated
        ones; the corpus sweep on gruff-py's own source produced zero
        candidate sites, so the rule ships enabled.

        Returns:
            Definition for the unsanitized-markdown-interpolation rule under
            the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unsanitized markdown interpolation",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag unwrapped dynamic label/url slots in markdown link shapes.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unwrapped link slot.
        """
        if unit.tree is None or "](" not in unit.source:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if isinstance(node, ast.JoinedStr):
                findings.extend(_joined_str_findings(definition, unit, node))
            elif isinstance(node, ast.Call):
                findings.extend(_format_call_findings(definition, unit, node))
        return findings


def _joined_str_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.JoinedStr,
) -> list[Finding]:
    template_parts: list[str] = []
    dynamic_values: list[ast.expr] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            template_parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            template_parts.append(_PLACEHOLDER)
            dynamic_values.append(value.value)
        else:
            return []
    return _link_slot_findings(definition, unit, node, "".join(template_parts), dynamic_values)


def _format_call_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.Call,
) -> list[Finding]:
    callee = node.func
    if not (isinstance(callee, ast.Attribute) and callee.attr == "format"):
        return []
    template_owner = callee.value
    if not (isinstance(template_owner, ast.Constant) and isinstance(template_owner.value, str)):
        return []
    template, dynamic_values = _resolve_format_fields(template_owner.value, node)
    if template is None:
        return []
    return _link_slot_findings(definition, unit, node, template, dynamic_values)


def _resolve_format_fields(
    template: str,
    node: ast.Call,
) -> tuple[str | None, list[ast.expr]]:
    """Replace ``{...}`` fields with placeholders mapped to their argument exprs."""
    keyword_arguments = {
        keyword.arg: keyword.value for keyword in node.keywords if keyword.arg is not None
    }
    dynamic_values: list[ast.expr] = []
    auto_index = 0
    resolved: list[str] = []
    last_end = 0
    for match in _FORMAT_FIELD_PATTERN.finditer(template):
        resolved.append(template[last_end : match.start()])
        last_end = match.end()
        field_name = match.group(1)
        if field_name == "":
            argument = node.args[auto_index] if auto_index < len(node.args) else None
            auto_index += 1
        elif field_name.isdigit():
            try:
                index = int(field_name)
            except ValueError:  # isdigit() accepts "²"-style digits int() rejects
                return None, []
            argument = node.args[index] if index < len(node.args) else None
        else:
            argument = keyword_arguments.get(field_name.split(".")[0].split("[")[0])
        if argument is None:
            return None, []
        resolved.append(_PLACEHOLDER)
        dynamic_values.append(argument)
    resolved.append(template[last_end:])
    return "".join(resolved), dynamic_values


def _link_slot_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    template: str,
    dynamic_values: list[ast.expr],
) -> list[Finding]:
    findings: list[Finding] = []
    for match in _LINK_PATTERN.finditer(template):
        for slot, group_index in (("label", 1), ("url", 2)):
            slot_text = match.group(group_index)
            first_value_index = template.count(_PLACEHOLDER, 0, match.start(group_index))
            for offset in range(slot_text.count(_PLACEHOLDER)):
                expression = dynamic_values[first_value_index + offset]
                if isinstance(expression, ast.Call):
                    continue
                findings.append(_build_finding(definition, unit, node, slot))
    return findings


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    slot: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"Markdown link {slot} interpolates a raw value; a {slot} containing "
            "a `](` delimiter injects its own link and redirects the rendered "
            "target. The value needs an escaping call before interpolation."
        ),
        file_path=unit.file.display_path,
        line=getattr(node, "lineno", 1),
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(node, "end_lineno", None),
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={"slot": slot},
    )
