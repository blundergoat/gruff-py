"""Detect raw values placed inside rendered Markdown link labels and URLs.

The rule recognizes f-strings and literal ``str.format`` link shapes, then asks
the local provenance index whether each dynamic slot came from a configured
sanitizer. CLI users reach this path when their source builds ``[label](url)``;
unknown wrappers and uncertain assignments remain visible as advisory findings.

Only those two shapes are inspected. Concatenation chains
(``"[" + a + "](" + b + ")"``) and percent formatting (``"[%s](%s)" % (a, b)``)
build the same link without being examined, so a clean result for a file is not
evidence that the file has no Markdown link injection.
"""

import ast
import re

from gruffpy.config.markdown_sanitizer_options import (
    DEFAULT_LABEL_SANITIZERS,
    DEFAULT_URL_SANITIZERS,
    LABEL_SANITIZERS_OPTION,
    URL_SANITIZERS_OPTION,
    validate_markdown_sanitizer_targets,
)
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._markdown_sanitizer_model import (
    MarkdownSlot,
    SanitizerResolution,
    expression_kind,
)
from gruffpy.rule.security._markdown_sanitizer_provenance import MarkdownSanitizerProvenance

_PLACEHOLDER_CHARACTER = "\x00"
_LINK_PATTERN = re.compile(r"\[([^\[\]]*)\]\(([^()]*)\)")
_FORMAT_FIELD_PATTERN = re.compile(r"\{([^{}:!]*)(?:[:!][^{}]*)?\}")
_LINK_SLOT_GROUPS: tuple[tuple[MarkdownSlot, int], ...] = (("label", 1), ("url", 2))
_REMEDIATION = (
    "Escape the interpolated value before it enters the link shape: strip or "
    "percent-encode `]`, `(`, and `)` in labels and urls (a markdown_label()/"
    "markdown_url() helper), then interpolate the escaped value."
)


class UnsanitizedMarkdownInterpolationRule(Rule):
    """Find Markdown links whose visible text or click target remains unproved.

    Users configure exact helpers per slot. The rule keeps literal and bounded
    assigned results quiet while explaining why raw or wrongly wrapped values fire.
    """

    ID = "security.unsanitized-markdown-interpolation"

    def definition(self) -> RuleDefinition:
        """Describe the advisory plus its generated slot-specific sanitizer defaults.

        Returns:
            Public rule definition used by config generation and rule documentation.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unsanitized markdown interpolation",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={
                LABEL_SANITIZERS_OPTION: list(DEFAULT_LABEL_SANITIZERS),
                URL_SANITIZERS_OPTION: list(DEFAULT_URL_SANITIZERS),
            },
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Return one advisory for each Markdown slot the user's code cannot prove safe.

        Args:
            unit: Parsed source file; a missing tree or no link marker means no findings.
            context: Resolved user config carrying exact sanitizer lists for both slots.

        Returns:
            Findings in source traversal order; empty means no unproved link slot was found.
        """
        # A parse failure or file without a Markdown link boundary has nothing to inspect here.
        if not isinstance(unit.tree, ast.Module) or "](" not in unit.source:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        label_targets = validate_markdown_sanitizer_targets(
            LABEL_SANITIZERS_OPTION,
            settings.options.get(
                LABEL_SANITIZERS_OPTION,
                definition.default_options[LABEL_SANITIZERS_OPTION],
            ),
        )
        url_targets = validate_markdown_sanitizer_targets(
            URL_SANITIZERS_OPTION,
            settings.options.get(
                URL_SANITIZERS_OPTION,
                definition.default_options[URL_SANITIZERS_OPTION],
            ),
        )
        provenance = MarkdownSanitizerProvenance.build(
            unit.tree,
            label_targets=set(label_targets),
            url_targets=set(url_targets),
        )
        findings: list[Finding] = []
        # Each link-building expression is evaluated against its statement-ordered proof state.
        for node in ast.walk(unit.tree):
            # F-strings expose their dynamic values directly to the link template parser.
            if isinstance(node, ast.JoinedStr):
                findings.extend(_joined_str_findings(definition, unit, node, provenance))
            # Literal `.format()` calls require field-to-argument resolution first.
            elif isinstance(node, ast.Call):
                findings.extend(_format_call_findings(definition, unit, node, provenance))
        return findings


def _joined_str_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.JoinedStr,
    provenance: MarkdownSanitizerProvenance,
) -> list[Finding]:
    """Map an f-string to link slots and return findings for its unproved values.

    Args:
        definition: Public rule metadata used to build findings.
        unit: User source file supplying path and location context.
        node: F-string expression detected in the parsed file.
        provenance: Per-expression safety index; empty state treats names as raw.

    Returns:
        Slot findings for this f-string; empty means it is not a link or every slot is safe.
    """
    static_text = "".join(value.value for value in node.values if isinstance(value, ast.Constant) and isinstance(value.value, str))
    placeholder = _placeholder_absent_from(static_text)
    template_parts: list[str] = []
    dynamic_values: list[ast.expr] = []
    # Every f-string component becomes static text or one ordered collision-free placeholder.
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            template_parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            template_parts.append(placeholder)
            dynamic_values.append(value.value)
        else:
            return []
    return _link_slot_findings(
        definition,
        unit,
        node,
        "".join(template_parts),
        placeholder,
        dynamic_values,
        provenance,
    )


def _format_call_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.Call,
    provenance: MarkdownSanitizerProvenance,
) -> list[Finding]:
    """Resolve a literal ``.format()`` link and report its unproved arguments.

    Args:
        definition: Public rule metadata used to build findings.
        unit: User source file supplying path and location context.
        node: Candidate call expression from the parsed file.
        provenance: Per-expression safety index for assigned and direct values.

    Returns:
        Slot findings for a supported literal template; empty for other calls or safe links.
    """
    callee = node.func
    # Calls other than literal-string `.format()` are sanitizer candidates, not link sinks.
    if not (isinstance(callee, ast.Attribute) and callee.attr == "format"):
        return []
    template_owner = callee.value
    # A dynamic format template does not give the scanner a stable Markdown link shape.
    if not (isinstance(template_owner, ast.Constant) and isinstance(template_owner.value, str)):
        return []
    template, placeholder, dynamic_values = _resolve_format_fields(template_owner.value, node)
    # Missing field arguments make the runtime template unresolved and unsuitable for a finding.
    if template is None:
        return []
    return _link_slot_findings(
        definition,
        unit,
        node,
        template,
        placeholder,
        dynamic_values,
        provenance,
    )


def _resolve_format_fields(
    template: str,
    node: ast.Call,
) -> tuple[str | None, str, list[ast.expr]]:
    """Replace format fields with placeholders paired to the user's argument expressions.

    Args:
        template: Literal format text; empty text contains no link fields.
        node: `.format()` call whose missing arguments make resolution return ``None``.

    Returns:
        Placeholder template, collision-free token, and ordered values. An unresolved
        field returns ``(None, token, [])``.
    """
    # Derive the placeholder from the field-stripped static text, not the raw
    # template: removing a ``{field}`` can splice the NUL runs on either side of
    # it into one longer run, so a token chosen against the raw template can
    # merge with adjacent static NULs and be over-counted in a slot (an
    # ``IndexError`` on the value list). This mirrors the f-string path, which
    # derives its token from the concatenated static constants.
    placeholder = _placeholder_absent_from(_FORMAT_FIELD_PATTERN.sub("", template))
    keyword_arguments = {keyword_argument.arg: keyword_argument.value for keyword_argument in node.keywords if keyword_argument.arg is not None}
    dynamic_values: list[ast.expr] = []
    auto_index = 0
    resolved: list[str] = []
    last_end = 0
    # Each field keeps its source order so label and URL values align with placeholders.
    for match in _FORMAT_FIELD_PATTERN.finditer(template):
        resolved.append(template[last_end : match.start()])
        last_end = match.end()
        field_name = match.group(1)
        # Attributes and indexes still resolve through their root format argument.
        root = field_name.split(".", 1)[0].split("[", 1)[0]
        # Empty fields consume the next positional argument the user supplied.
        if root == "":
            argument = node.args[auto_index] if auto_index < len(node.args) else None
            auto_index += 1
        # Numeric roots such as `{0.name}` select an explicit positional argument.
        elif root.isdigit():
            try:
                index = int(root)
            # A user can write a Unicode digit such as `²` that `isdigit()` accepts but int rejects.
            except ValueError:
                return None, placeholder, []
            argument = node.args[index] if index < len(node.args) else None
        else:
            argument = keyword_arguments.get(root)
        # A missing positional/keyword value would make this user template fail at runtime.
        if argument is None:
            return None, placeholder, []
        resolved.append(placeholder)
        dynamic_values.append(argument)
    resolved.append(template[last_end:])
    return "".join(resolved), placeholder, dynamic_values


def _placeholder_absent_from(static_text: str) -> str:
    """Return a NUL token that cannot be mistaken for user-authored static text.

    Args:
        static_text: Decoded literal text from one f-string or format template.

    Returns:
        One or more NUL characters absent from the static text.
    """
    placeholder = _PLACEHOLDER_CHARACTER
    while placeholder in static_text:
        placeholder += _PLACEHOLDER_CHARACTER
    return placeholder


def _link_slot_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    template: str,
    placeholder: str,
    dynamic_values: list[ast.expr],
    provenance: MarkdownSanitizerProvenance,
) -> list[Finding]:
    """Return findings for dynamic label/URL placeholders without a safety proof.

    Args:
        definition: Public rule metadata used for every emitted finding.
        unit: User file supplying stable path and source location.
        node: Whole link expression used for the existing finding location.
        template: Link text with placeholders; empty means no detected link shape.
        placeholder: Per-template token absent from all decoded static text.
        dynamic_values: Expressions aligned to placeholders; empty means a literal link.
        provenance: Statement-ordered safety index for each expression and slot.

    Returns:
        One finding per unproved slot value; empty means no matching dynamic link remains.
    """
    findings: list[Finding] = []
    # A source expression may contain more than one Markdown link shape.
    for match in _LINK_PATTERN.finditer(template):
        # Labels and URLs receive separate configured sanitizer proofs.
        for markdown_slot, group_index in _LINK_SLOT_GROUPS:
            slot_text = match.group(group_index)
            first_value_index = template.count(placeholder, 0, match.start(group_index))
            # Every placeholder in this rendered slot needs its own proof.
            for offset in range(slot_text.count(placeholder)):
                expression = dynamic_values[first_value_index + offset]
                safety = provenance.proof_for(expression, markdown_slot)
                # A proved sanitizer/literal path produces no warning for the user.
                if safety.is_safe:
                    continue
                findings.append(
                    _build_finding(
                        definition,
                        unit,
                        node,
                        markdown_slot,
                        expression,
                        safety.sanitizer_resolution,
                    )
                )
    return findings


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    slot: MarkdownSlot,
    expression: ast.expr,
    sanitizer_resolution: SanitizerResolution,
) -> Finding:
    """Build the frozen finding text plus additive sanitizer explanation metadata.

    Args:
        definition: Public severity, confidence, pillar, and rule id.
        unit: User source file supplying the displayed path.
        node: Whole link expression preserving the existing location contract.
        slot: Visible label or clickable URL that remained unsafe.
        expression: Unproved AST value used only for its bounded metadata kind.
        sanitizer_resolution: Stable reason the configured sanitizer proof failed.

    Returns:
        Advisory finding whose message and location remain identity-compatible.
    """
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
        metadata={
            "slot": slot,
            "expressionKind": expression_kind(expression),
            "sanitizerResolution": sanitizer_resolution,
        },
    )
