"""Guide users toward predicate names for scalar Boolean declarations.

The CLI reaches this rule after parsing a Python file and reports functions or
attributes whose exact scalar Boolean annotation conflicts with their name.
Containers, callables, and mixed unions stay outside this naming journey.
Quoted annotations are parsed as bounded syntax and are never evaluated.
"""

import ast
import re
from enum import StrEnum

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    _decorator_name,
    has_dataclass_decorator,
    has_framework_base,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain

_BOOLEAN_PREFIXES: frozenset[str] = frozenset(
    {
        "accepts",
        "allows",
        "are",
        "can",
        "check",
        "checks",
        "contains",
        "did",
        "do",
        "does",
        "expects",
        "has",
        "is",
        "looks",
        "matches",
        "must",
        "needs",
        "produces",
        "requires",
        "returns",
        "should",
        "supports",
        "uses",
        "validates",
        "was",
        "will",
    }
)
# Auxiliary and modal markers ask a yes/no question as a whole segment in any position, so
# ``_state_is_attributed_to_patient`` and ``_sentence_needs_wording_review`` already read as predicates.
# Relationship verbs such as ``contains`` stay positional: mid-name they usually name an object.
_BOOLEAN_AUXILIARY_MARKERS: frozenset[str] = frozenset({"are", "can", "did", "does", "has", "is", "must", "needs", "should", "was", "will"})
# Relationship verbs express the user's Boolean answer only at the end of a name
# (for example, ``input_affirms`` or ``source_contains``).
_BOOLEAN_VERB_SUFFIXES: frozenset[str] = frozenset({"affirms", "contains", "declines", "matches"})
# State adjectives communicate the user's Boolean intent only as the final token.
_BOOLEAN_ADJECTIVES: frozenset[str] = frozenset(
    {
        "active",
        "alive",
        "applicable",
        "available",
        "default",
        "disabled",
        "empty",
        "enabled",
        "excluded",
        "frozen",
        "included",
        "interactive",
        "invalid",
        "optional",
        "present",
        "ready",
        "required",
        "valid",
        "verbose",
        "visible",
    }
)
_BOOLEAN_PREFIX_PATTERNS: tuple[str, ...] = (
    "exclude_",
    "include_",
    "no_",
    "with_",
    "without_",
)
_BOOLEAN_SUFFIX_PATTERNS: tuple[str, ...] = (
    "_bool",
    "_disabled",
    "_enabled",
    "_flag",
    "_optional",
    "_required",
)
_DEFAULT_ACCEPTED_BOOLEAN_NAMES: frozenset[str] = frozenset(
    {
        "all",
        "apply",
        "check",
        "dev",
        "enabled",
        "force",
        "fresh",
        "harness",
        "json",
        "ok",
        "verbose",
        "yes",
    }
)

_MAX_ANNOTATION_DEPTH = 24
_OPTIONAL_ANNOTATION_TARGETS = frozenset({"Optional", "typing.Optional"})
_UNION_ANNOTATION_TARGETS = frozenset({"Union", "typing.Union"})
_ANNOTATED_ANNOTATION_TARGETS = frozenset({"Annotated", "typing.Annotated"})


class _BooleanAnnotationShape(StrEnum):
    """Describe how a user's declaration proves scalar Boolean intent.

    Finding metadata exposes the three Boolean values so UI and agent users can
    understand the match. ``OTHER`` is internal and never reaches a finding.
    """

    BOOL = "bool"
    OPTIONAL_BOOL = "optional-bool"
    ANNOTATED_BOOL = "annotated-bool"
    OTHER = "other"


class BooleanPrefixRule(Rule):
    """Report scalar Boolean declarations whose names hide predicate intent.

    Users reach this rule during a normal CLI scan. Exact annotation shapes
    decide applicability before existing naming and boundary exemptions run.
    """

    ID = "naming.boolean-prefix"

    def definition(self) -> RuleDefinition:
        """Describe the advisory users can tune for exact boundary names.

        Returns:
            Definition for the boolean-prefix rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Boolean prefix",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"acceptedBooleanNames": sorted(_DEFAULT_ACCEPTED_BOOLEAN_NAMES)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Return naming guidance for exact scalar Boolean declarations.

        Args:
            unit: Parsed user file; a missing tree means parsing failed and no
                AST naming guidance can be produced.
            context: Active rule settings, including exact accepted boundary
                names; empty overrides retain the registered defaults.

        Returns:
            Findings visible in the scan; empty means no declaration needs a
            clearer Boolean-intent name.
        """
        # A user file with no AST cannot provide reliable annotation structure.
        if unit.tree is None:
            return []
        # Test declarations are user examples, not production naming contracts.
        if _is_test_file(unit.file.display_path):
            return []
        rule_definition = self.definition()
        accepted_boolean_names = _accepted_boolean_names(context, rule_definition)
        user_findings: list[Finding] = []

        # Each declaration is checked so the report points at the user's exact name.
        for candidate_node in ast.walk(unit.tree):
            finding = self._finding_for_node(
                unit,
                rule_definition,
                candidate_node,
                accepted_boolean_names,
            )
            # No finding means the declaration is non-Boolean, exempt, or clearly named.
            if finding is not None:
                user_findings.append(finding)
        return user_findings

    def _finding_for_node(
        self,
        unit: AnalysisUnit,
        rule_definition: RuleDefinition,
        candidate_node: ast.AST,
        accepted_boolean_names: frozenset[str],
    ) -> Finding | None:
        """Route one parsed declaration to the matching user-facing check.

        Args:
            unit: User file that supplies the report path.
            rule_definition: Stable severity and rule identity for the finding.
            candidate_node: Parsed node; unrelated nodes return ``None``.
            accepted_boolean_names: Exact names the user's config permits;
                empty means every name must express Boolean intent structurally.

        Returns:
            One finding for an affected declaration, otherwise ``None``.
        """
        # Function returns are the first Boolean declaration users encounter.
        if isinstance(candidate_node, ast.FunctionDef | ast.AsyncFunctionDef):
            return self._function_finding(
                unit,
                rule_definition,
                candidate_node,
                accepted_boolean_names,
            )
        # Annotated attributes share the same structural annotation contract.
        if isinstance(candidate_node, ast.AnnAssign):
            return self._attribute_finding(
                unit,
                rule_definition,
                candidate_node,
                accepted_boolean_names,
            )
        return None

    def _function_finding(
        self,
        unit: AnalysisUnit,
        rule_definition: RuleDefinition,
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
        accepted_boolean_names: frozenset[str],
    ) -> Finding | None:
        """Build guidance for one scalar Boolean function return.

        Args:
            unit: User file that supplies the report path.
            rule_definition: Stable finding policy for the rule.
            function_node: Function declaration being reviewed.
            accepted_boolean_names: Exact config exemptions; empty means none.

        Returns:
            Function finding, or ``None`` when shape/name/exemptions are safe.
        """
        # Dunder and override names come from Python or inherited user contracts.
        if _is_dunder(function_node.name) or _has_override_decorator(function_node):
            return None
        annotation_shape = _function_return_annotation_shape(function_node)
        # Non-scalar annotations do not ask the user to rename the function.
        if annotation_shape is _BooleanAnnotationShape.OTHER:
            return None
        # A clear predicate name or exact configured boundary needs no guidance.
        if _has_boolean_prefix(function_node.name, accepted_boolean_names):
            return None
        return self._finding(
            unit,
            rule_definition,
            function_node.name,
            function_node.lineno,
            declaration_kind="function",
            annotation_shape=annotation_shape,
        )

    def _attribute_finding(
        self,
        unit: AnalysisUnit,
        rule_definition: RuleDefinition,
        attribute_node: ast.AnnAssign,
        accepted_boolean_names: frozenset[str],
    ) -> Finding | None:
        """Build guidance for one scalar Boolean annotated attribute.

        Args:
            unit: User file that supplies the report path.
            rule_definition: Stable finding policy for the rule.
            attribute_node: Annotated assignment being reviewed.
            accepted_boolean_names: Exact config exemptions; empty means none.

        Returns:
            Attribute finding, or ``None`` when shape/name/exemptions are safe.
        """
        # Complex targets do not expose one renameable user-facing identifier.
        if not isinstance(attribute_node.target, ast.Name):
            return None
        attribute_name = attribute_node.target.id
        # Contract or clearly Boolean names do not need a rename suggestion.
        if _is_dunder(attribute_name) or _has_boolean_prefix(
            attribute_name,
            accepted_boolean_names,
        ):
            return None
        annotation_shape = _boolean_annotation_shape(attribute_node.annotation)
        # Containers and other non-scalar annotations stay out of the report.
        if annotation_shape is _BooleanAnnotationShape.OTHER:
            return None
        # Uppercase constants keep the user's conventional API spelling.
        if _is_upper_snake_constant(attribute_node, attribute_name):
            return None
        # Schema fields preserve wire names that downstream users may consume.
        if _is_schema_field(attribute_node):
            return None
        return self._finding(
            unit,
            rule_definition,
            attribute_name,
            attribute_node.target.lineno,
            declaration_kind="attribute",
            annotation_shape=annotation_shape,
        )

    def _finding(
        self,
        unit: AnalysisUnit,
        rule_definition: RuleDefinition,
        declaration_name: str,
        declaration_line: int,
        declaration_kind: str,
        annotation_shape: _BooleanAnnotationShape,
    ) -> Finding:
        """Create the stable finding plus its additive shape explanation.

        Args:
            unit: User file that supplies the report path.
            rule_definition: Stable severity and identity policy.
            declaration_name: Name shown in the finding and remediation.
            declaration_line: One-based source line shown to the user.
            declaration_kind: ``function`` or ``attribute`` report label.
            annotation_shape: Proven scalar shape; ``OTHER`` is never passed.

        Returns:
            Complete user-facing finding with frozen identity inputs.
        """
        return Finding(
            rule_id=rule_definition.id,
            message=_boolean_intent_message(declaration_kind, declaration_name),
            file_path=unit.file.display_path,
            line=declaration_line,
            severity=rule_definition.default_severity,
            pillar=rule_definition.pillar,
            tier=rule_definition.tier,
            confidence=rule_definition.confidence,
            end_line=declaration_line,
            symbol=declaration_name,
            remediation=(f"Rename {declaration_name!r} with a boolean prefix (e.g. ``is_{_strip_lead(declaration_name)}``)."),
            secondary_pillars=rule_definition.secondary_pillars,
            metadata={
                "identifier": declaration_name,
                "kind": declaration_kind,
                "annotationShape": annotation_shape.value,
            },
        )


def _is_dunder(declaration_name: str) -> bool:
    """Return whether Python owns the declaration's double-underscore name.

    Args:
        declaration_name: User declaration name; empty text is not a dunder.

    Returns:
        ``True`` when the scan should preserve Python's special spelling.
    """
    return declaration_name.startswith("__") and declaration_name.endswith("__") and len(declaration_name) > 4


def _has_override_decorator(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether an inherited contract controls the user's method name.

    Args:
        function_node: Function declaration; an empty decorator list means the
            user owns the name locally.

    Returns:
        ``True`` when an ``@override`` spelling exempts the method.
    """
    # Each decorator spelling is reduced to its user-visible leaf name.
    return any(_decorator_name(decorator).split(".")[-1] == "override" for decorator in function_node.decorator_list)


def _accepted_boolean_names(
    context: RuleContext,
    rule_definition: RuleDefinition,
) -> frozenset[str]:
    """Resolve exact boundary names accepted for the user's current scan.

    Args:
        context: Active project configuration.
        rule_definition: Registered defaults used when no override is present.

    Returns:
        Lowercase exact names; empty means no boundary-name exemption.
    """
    rule_settings = context.settings_for(rule_definition)
    # A configured list replaces the defaults for this user's scan.
    if rule_settings.has_option("acceptedBooleanNames"):
        configured_names = rule_settings.string_list_option("acceptedBooleanNames")
    else:
        # No override keeps the reviewed registry vocabulary visible to users.
        configured_names = list(rule_definition.default_options["acceptedBooleanNames"])
    # Every configured spelling is compared case-insensitively and exactly.
    return frozenset(configured_name.lower() for configured_name in configured_names)


def _has_boolean_prefix(
    declaration_name: str,
    accepted_boolean_names: frozenset[str],
) -> bool:
    """Return whether a declaration already communicates Boolean intent.

    Args:
        declaration_name: Name shown to the user; underscores alone are empty intent.
        accepted_boolean_names: Exact configured names; empty means none.

    Returns:
        ``True`` when the user does not need a rename suggestion.
    """
    visible_name = declaration_name.lstrip("_")
    # A name containing only privacy underscores gives the reviewer no intent.
    if not visible_name:
        return False
    lowercase_name = visible_name.lower()
    semantic_tokens = lower_tokens(visible_name)
    # A tokenizer miss means the UI has no Boolean word to recognize.
    if not semantic_tokens:
        return False
    # An auxiliary or modal token asks a clear yes/no question in any name position.
    contains_auxiliary_marker = any(token in _BOOLEAN_AUXILIARY_MARKERS for token in semantic_tokens)
    return (
        lowercase_name in accepted_boolean_names
        or lowercase_name in _BOOLEAN_PREFIXES
        or lowercase_name in _BOOLEAN_ADJECTIVES
        or semantic_tokens[0] in _BOOLEAN_PREFIXES
        or semantic_tokens[-1] in _BOOLEAN_ADJECTIVES
        or semantic_tokens[-1] in _BOOLEAN_VERB_SUFFIXES
        or contains_auxiliary_marker
        or lowercase_name.startswith(_BOOLEAN_PREFIX_PATTERNS)
        or lowercase_name.endswith(_BOOLEAN_SUFFIX_PATTERNS)
    )


def _joined(vocabulary: frozenset[str] | tuple[str, ...]) -> str:
    """Render one accepted vocabulary for a user-facing message, sorted so reports stay stable.

    Args:
        vocabulary: A constant this module matches names against.

    Returns:
        Comma-separated entries in sorted order.
    """
    return ", ".join(sorted(vocabulary))


def _boolean_intent_message(declaration_kind: str, declaration_name: str) -> str:
    """Explain a finding with the vocabulary the matcher accepts, generated from its constants.

    Args:
        declaration_kind: ``function`` or ``attribute`` report label.
        declaration_name: Name shown to the user.

    Returns:
        A message that names every accepted form, so it cannot drift from what the rule accepts.
    """
    return (
        f"{declaration_kind.capitalize()} {declaration_name!r} returns / is bool but its name states no boolean intent. "
        f"Accepted: a leading marker ({_joined(_BOOLEAN_PREFIXES)}); "
        f"one of these markers as a segment anywhere ({_joined(_BOOLEAN_AUXILIARY_MARKERS)}); "
        f"a final state adjective ({_joined(_BOOLEAN_ADJECTIVES)}); "
        f"a final relationship verb ({_joined(_BOOLEAN_VERB_SUFFIXES)}); "
        f"a prefix ({_joined(_BOOLEAN_PREFIX_PATTERNS)}); "
        f"a suffix ({_joined(_BOOLEAN_SUFFIX_PATTERNS)}); "
        "or a name listed in acceptedBooleanNames."
    )


def _function_return_annotation_shape(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> _BooleanAnnotationShape:
    """Classify the return annotation that drives a user's function finding.

    Args:
        function_node: Parsed function; no return annotation means no naming guidance.

    Returns:
        Exact scalar shape, or ``OTHER`` when the return is absent/non-Boolean.
    """
    return_annotation = function_node.returns
    # An unannotated function gives the scanner no static Boolean contract.
    if return_annotation is None:
        return _BooleanAnnotationShape.OTHER
    return _boolean_annotation_shape(return_annotation)


def _boolean_annotation_shape(
    annotation: ast.expr,
    *,
    remaining_depth: int = _MAX_ANNOTATION_DEPTH,
) -> _BooleanAnnotationShape:
    """Classify only exact scalar Boolean syntax without importing user code.

    Args:
        annotation: Parsed annotation expression from the user's source.
        remaining_depth: Wrapper budget; zero means the source is too deeply
            nested to classify safely.

    Returns:
        Stable scalar shape, or ``OTHER`` for containers and unproved syntax.
    """
    # Excessive generated nesting stays quiet instead of exhausting the scan.
    if remaining_depth <= 0:
        return _BooleanAnnotationShape.OTHER
    # A direct bool annotation is the narrowest user-visible scalar contract.
    if _is_bool_name(annotation):
        return _BooleanAnnotationShape.BOOL
    # Explicit string annotations are untrusted source that needs bounded parsing.
    if isinstance(annotation, ast.Constant):
        # Only text constants can represent a quoted type annotation.
        if isinstance(annotation.value, str):
            return _quoted_annotation_shape(annotation.value, remaining_depth - 1)
        return _BooleanAnnotationShape.OTHER
    # PEP 604 optional syntax must be exactly bool plus None in either order.
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _optional_pair_shape(
            annotation.left,
            annotation.right,
            remaining_depth - 1,
        )
    # All supported typing wrappers are subscript expressions with exact targets.
    if not isinstance(annotation, ast.Subscript):
        return _BooleanAnnotationShape.OTHER

    annotation_target = _annotation_target_name(annotation.value)
    # Optional accepts one direct scalar Boolean parameter.
    if annotation_target in _OPTIONAL_ANNOTATION_TARGETS:
        return _optional_subscript_shape(annotation.slice, remaining_depth - 1)
    # Union accepts exactly the bool/None optional pair, never mixed members.
    if annotation_target in _UNION_ANNOTATION_TARGETS:
        return _union_subscript_shape(annotation.slice, remaining_depth - 1)
    # Annotated may wrap a supported scalar/optional shape plus metadata.
    if annotation_target in _ANNOTATED_ANNOTATION_TARGETS:
        return _annotated_subscript_shape(annotation.slice, remaining_depth - 1)
    return _BooleanAnnotationShape.OTHER


def _quoted_annotation_shape(
    annotation_text: str,
    remaining_depth: int,
) -> _BooleanAnnotationShape:
    """Parse one quoted annotation as inert expression syntax for the scan.

    Args:
        annotation_text: User-authored type text; empty text is unproved.
        remaining_depth: Remaining wrapper budget after entering the string.

    Returns:
        Parsed scalar shape, or ``OTHER`` for invalid/deep/executable syntax.
    """
    # An empty quoted annotation provides no Boolean contract to the reviewer.
    if not annotation_text.strip():
        return _BooleanAnnotationShape.OTHER
    try:
        parsed_annotation = ast.parse(annotation_text, mode="eval")
    # A user can write `-> "bool["` or generated deeply nested text.
    except (SyntaxError, ValueError, RecursionError):
        return _BooleanAnnotationShape.OTHER
    # Eval mode normally returns Expression; any other parser result is unproved.
    if not isinstance(parsed_annotation, ast.Expression):
        return _BooleanAnnotationShape.OTHER
    return _boolean_annotation_shape(
        parsed_annotation.body,
        remaining_depth=remaining_depth,
    )


def _annotation_target_name(annotation_target: ast.expr) -> str:
    """Return an exact supported wrapper spelling from the user's annotation.

    Args:
        annotation_target: Expression before ``[...]`` in the annotation.

    Returns:
        Bare or ``typing.*`` target; empty means an unsupported dotted target.
    """
    # Bare Optional/Union/Annotated spellings are common after from-imports.
    if isinstance(annotation_target, ast.Name):
        return annotation_target.id
    # Only the explicit typing module receives dotted-wrapper equivalence.
    if isinstance(annotation_target, ast.Attribute) and isinstance(annotation_target.value, ast.Name) and annotation_target.value.id == "typing":
        return f"typing.{annotation_target.attr}"
    return ""


def _optional_subscript_shape(
    annotation_parameter: ast.expr,
    remaining_depth: int,
) -> _BooleanAnnotationShape:
    """Classify exact ``Optional[bool]`` syntax for the user's report.

    Args:
        annotation_parameter: Expression inside the Optional brackets.
        remaining_depth: Wrapper budget; zero classifies as ``OTHER``.

    Returns:
        ``OPTIONAL_BOOL`` only for one direct Boolean parameter.
    """
    # A tuple means the user supplied multiple Optional parameters, which is invalid.
    if isinstance(annotation_parameter, ast.Tuple):
        return _BooleanAnnotationShape.OTHER
    parameter_shape = _boolean_annotation_shape(
        annotation_parameter,
        remaining_depth=remaining_depth,
    )
    # Optional wrappers remain exact and do not absorb arbitrary nested types.
    if parameter_shape is _BooleanAnnotationShape.BOOL:
        return _BooleanAnnotationShape.OPTIONAL_BOOL
    return _BooleanAnnotationShape.OTHER


def _union_subscript_shape(
    annotation_parameters: ast.expr,
    remaining_depth: int,
) -> _BooleanAnnotationShape:
    """Classify exact two-member ``Union[bool, None]`` syntax.

    Args:
        annotation_parameters: Union slice from the user's source.
        remaining_depth: Wrapper budget; zero classifies as ``OTHER``.

    Returns:
        ``OPTIONAL_BOOL`` for the exact optional pair, otherwise ``OTHER``.
    """
    # A valid optional Union supplies exactly two comma-separated members.
    if not isinstance(annotation_parameters, ast.Tuple):
        return _BooleanAnnotationShape.OTHER
    # Extra union members change the user's return contract beyond scalar Boolean.
    if len(annotation_parameters.elts) != 2:
        return _BooleanAnnotationShape.OTHER
    return _optional_pair_shape(
        annotation_parameters.elts[0],
        annotation_parameters.elts[1],
        remaining_depth,
    )


def _optional_pair_shape(
    first_member: ast.expr,
    second_member: ast.expr,
    remaining_depth: int,
) -> _BooleanAnnotationShape:
    """Classify one unordered bool/None pair without descendant search.

    Args:
        first_member: First PEP 604 or Union member.
        second_member: Second PEP 604 or Union member.
        remaining_depth: Wrapper budget; zero classifies as ``OTHER``.

    Returns:
        ``OPTIONAL_BOOL`` only when the members are direct ``bool`` and ``None``.
    """
    # A depleted budget keeps even a simple inner pair from bypassing depth limits.
    if remaining_depth <= 0:
        return _BooleanAnnotationShape.OTHER
    # Users may place None first in either optional spelling.
    if _is_none_annotation(first_member) and _is_bool_name(second_member):
        return _BooleanAnnotationShape.OPTIONAL_BOOL
    # The conventional bool-first spelling has the same report meaning.
    if _is_bool_name(first_member) and _is_none_annotation(second_member):
        return _BooleanAnnotationShape.OPTIONAL_BOOL
    return _BooleanAnnotationShape.OTHER


def _annotated_subscript_shape(
    annotation_parameters: ast.expr,
    remaining_depth: int,
) -> _BooleanAnnotationShape:
    """Classify Annotated metadata around a supported scalar Boolean shape.

    Args:
        annotation_parameters: Annotated slice including type and metadata.
        remaining_depth: Wrapper budget; zero classifies as ``OTHER``.

    Returns:
        ``ANNOTATED_BOOL`` when the first parameter is a supported scalar shape.
    """
    # Annotated requires one type plus at least one metadata value.
    if not isinstance(annotation_parameters, ast.Tuple):
        return _BooleanAnnotationShape.OTHER
    # Missing metadata is not a valid Annotated contract for the user.
    if len(annotation_parameters.elts) < 2:
        return _BooleanAnnotationShape.OTHER
    wrapped_shape = _boolean_annotation_shape(
        annotation_parameters.elts[0],
        remaining_depth=remaining_depth,
    )
    # Metadata may wrap direct, optional, or already annotated Boolean syntax.
    if wrapped_shape in {
        _BooleanAnnotationShape.BOOL,
        _BooleanAnnotationShape.OPTIONAL_BOOL,
        _BooleanAnnotationShape.ANNOTATED_BOOL,
    }:
        return _BooleanAnnotationShape.ANNOTATED_BOOL
    return _BooleanAnnotationShape.OTHER


def _is_none_annotation(annotation: ast.expr) -> bool:
    """Return whether a union member is the literal ``None`` type spelling.

    Args:
        annotation: One user-authored union member.

    Returns:
        ``True`` only for literal ``None``; arbitrary None-like names stay false.
    """
    return isinstance(annotation, ast.Constant) and annotation.value is None


def _is_bool_name(annotation_node: ast.AST) -> bool:
    """Return whether one annotation node is the direct builtin name ``bool``.

    Args:
        annotation_node: Parsed user syntax; non-name nodes return ``False``.

    Returns:
        ``True`` only for the exact terminal name.
    """
    return isinstance(annotation_node, ast.Name) and annotation_node.id == "bool"


def _strip_lead(declaration_name: str) -> str:
    """Return the visible name used in the user's rename example.

    Args:
        declaration_name: Original name; empty text stays empty in remediation.

    Returns:
        Name without privacy underscores, or the original when that is empty.
    """
    # All-underscore names retain their spelling so remediation never becomes blank.
    return declaration_name.lstrip("_") or declaration_name


_UPPER_SNAKE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*$")


def _is_upper_snake_constant(
    attribute_node: ast.AnnAssign,
    attribute_name: str,
) -> bool:
    """Preserve conventional Boolean constants in the user's public source.

    Args:
        attribute_node: Annotated assignment whose parents reveal its scope.
        attribute_name: Candidate name; empty text is not an uppercase constant.

    Returns:
        ``True`` for module/class uppercase constants that should not be renamed.
    """
    # A mixed/lowercase attribute is not using the constant-name convention.
    if not _UPPER_SNAKE_PATTERN.fullmatch(attribute_name):
        return False
    # Module and class parents make the uppercase declaration user-visible state.
    return any(isinstance(parent_node, ast.Module | ast.ClassDef) for parent_node in parent_chain(attribute_node))


def _is_schema_field(attribute_node: ast.AnnAssign) -> bool:
    """Return whether a field name belongs to a user-facing schema contract.

    Args:
        attribute_node: Annotated assignment; no class parent means no schema.

    Returns:
        ``True`` when renaming could break DTO, dataclass, or wire consumers.
    """
    # Parent order finds the nearest class that owns the user's field name.
    for parent_node in reversed(parent_chain(attribute_node)):
        # Framework/dataclass classes expose field names beyond local Python code.
        if isinstance(parent_node, ast.ClassDef):
            return has_framework_base(parent_node) or has_dataclass_decorator(parent_node)
    return False


def _is_test_file(display_path: str) -> bool:
    """Return whether a report path represents user test/example code.

    Args:
        display_path: User-visible path; empty text is treated as production input.

    Returns:
        ``True`` for tests directories or a root-level ``test_*.py`` file.
    """
    normalized_path = display_path.replace("\\", "/").lower()
    file_name = normalized_path.rsplit("/", 1)[-1]
    # Any tests directory is example/verification code rather than product API.
    if normalized_path.startswith("tests/") or "/tests/" in normalized_path:
        return True
    # A root-level pytest filename receives the same user-facing exemption.
    return "/" not in normalized_path and file_name.startswith("test_") and file_name.endswith(".py")
