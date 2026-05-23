"""Parameter name doesn't match its type-hint role.

When a parameter is annotated ``repo: Repository``, the conventional name is
``repository`` - the short ``repo`` form makes calls less self-documenting.

Detection:

- Parameter has a type annotation with a class-like name (Title-cased ast.Name).
- Configurable suffix list strips trailing role-words (``Service``,
  ``Repository``, ``Protocol``, ``ABC``, ``Type``).
- The resulting type root, lowercased, is compared against the parameter name
  in snake_case form.

Per-rule option ``ignoredParameterNames`` lets users allowlist short names
they want to keep (e.g. ``id``, ``ctx``).
"""

import ast
import re
from dataclasses import dataclass

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.naming._allowlists import DEFAULT_NAMING_ABBREVIATIONS
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule

# Framework-idiomatic parameter names that match many annotation shapes by
# convention rather than by snake-case derivation. `websocket` is the canonical
# lowercase spelling across Starlette / FastAPI / the `websockets` library
# (suggesting `web_socket` is wrong); `req` / `request` are the standard
# FastAPI handler parameter names; `ws` / `msg` are the equally idiomatic
# short forms.
_ACCEPTED_PARAMETER_NAMES: frozenset[str] = frozenset({"websocket", "req", "request", "ws", "msg"})
_TRIM_SUFFIXES: tuple[str, ...] = (
    "Service",
    "Repository",
    "Protocol",
    "ABC",
    "Type",
    "Adapter",
    "Provider",
)
_HEAD_NOUN_SUFFIX_TOKENS: frozenset[str] = frozenset({"item", "like", "node"})
_IGNORED_TYPE_NAMES: frozenset[str] = frozenset({"Any"})
_PATH_ROLE_TOKENS: frozenset[str] = frozenset({"path", "root", "file", "dir", "directory"})
_COLLECTION_ROLE_NAMES: frozenset[str] = frozenset({"members"})
_GROUP_ROLE_TOKENS: frozenset[str] = frozenset({"root"})
_COLLECTION_TYPES: frozenset[str] = frozenset(
    {
        "list",
        "set",
        "tuple",
        "frozenset",
        "Sequence",
        "Iterable",
        "Collection",
        "Mapping",
        "MutableMapping",
    }
)
_WRAPPER_TYPES: frozenset[str] = frozenset({"Optional", "Union", "Annotated"})

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class _ParameterMismatch:
    """One parameter whose name diverges from its annotation's canonical form."""

    name: str
    expected: str
    suggested: str
    line: int


class ParameterTypeNameRule(Rule):
    """Detect parameters whose name does not match the snake_case root of their type annotation."""

    ID = "naming.parameter-type-name"

    def definition(self) -> RuleDefinition:
        """Describe the parameter-type-name rule with a configurable ignore list.

        ``ignoredParameterNames`` defaults to the project's accepted-naming
        abbreviations set (``id``, ``ctx``, etc.) so common short forms
        don't fire when their type would suggest a longer canonical name.

        Returns:
            Definition for the parameter-type-name rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Parameter type name",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"ignoredParameterNames": list(DEFAULT_NAMING_ABBREVIATIONS)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag parameters whose name diverges from their annotation's canonical form.

        Strips role suffixes (``Service``, ``Repository``, ``Protocol``,
        ``ABC``, ``Type``, ``Adapter``, ``Provider``) before comparing.
        Accepts plurals for collection-typed parameters (``list[User]`` ->
        ``users`` is fine) and shared-token names. Test files are skipped.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the
                ``ignoredParameterNames`` option.

        Returns:
            One finding per parameter whose name doesn't match the type's
            canonical name (or accepted short forms / plurals / shared tokens).
        """
        if unit.tree is None:
            return []
        if _is_test_file(unit.file.display_path):
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        ignored = _ignored_parameter_names(settings.options.get("ignoredParameterNames"))
        return [
            _parameter_mismatch_finding(unit, definition, mismatch)
            for mismatch in _parameter_mismatches(unit.tree, ignored)
        ]


def _ignored_parameter_names(configured: object) -> frozenset[str]:
    if not isinstance(configured, list) or not all(isinstance(name, str) for name in configured):
        return frozenset(DEFAULT_NAMING_ABBREVIATIONS)
    return frozenset(configured)


def _parameter_mismatches(tree: ast.AST, ignored: frozenset[str]) -> list[_ParameterMismatch]:
    mismatches: list[_ParameterMismatch] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for arg in _function_parameters(node):
            expected = _expected_parameter_name(arg, ignored)
            if expected is not None:
                mismatches.append(
                    _ParameterMismatch(
                        arg.arg,
                        expected,
                        _suggested_parameter_name(arg.annotation, expected),
                        arg.lineno,
                    )
                )
    return mismatches


def _function_parameters(node: FunctionNode) -> list[ast.arg]:
    return list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)


def _expected_parameter_name(arg: ast.arg, ignored: frozenset[str]) -> str | None:
    if arg.annotation is None:
        return None
    if (
        arg.arg.startswith("_")
        or arg.arg in ignored
        or arg.arg in {"self", "cls"}
        or arg.arg in _ACCEPTED_PARAMETER_NAMES
    ):
        return None
    expected = _expected_name(arg.annotation)
    if expected is None or _is_acceptable_parameter_name(arg, expected):
        return None
    return expected


def _is_acceptable_parameter_name(arg: ast.arg, expected: str) -> bool:
    if arg.arg == expected:
        return True
    if expected.startswith(arg.arg) and len(arg.arg) >= 2:
        return True
    annotation = arg.annotation
    if (
        annotation is not None
        and _is_collection_annotation(annotation)
        and (_has_plural_match(arg.arg, expected) or arg.arg in _COLLECTION_ROLE_NAMES)
    ):
        return True
    if expected == "group" and bool(set(lower_tokens(arg.arg)) & _GROUP_ROLE_TOKENS):
        return True
    if _has_shared_token(arg.arg, expected):
        return True
    return _has_shared_path_role(arg.arg, expected)


def _parameter_mismatch_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    mismatch: _ParameterMismatch,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"Parameter {mismatch.name!r} annotated as a complex type; "
            f"prefer the canonical name ``{mismatch.suggested}``."
        ),
        file_path=unit.file.display_path,
        line=mismatch.line,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=mismatch.line,
        symbol=mismatch.name,
        remediation=f"Rename ``{mismatch.name}`` to ``{mismatch.suggested}``.",
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "parameter": mismatch.name,
            "expected": mismatch.expected,
            "suggested": mismatch.suggested,
        },
    )


def _expected_name(annotation: ast.expr) -> str | None:
    """Return the canonical snake_case name for *annotation*, or None when the
    annotation is not a single Title-cased class-like name."""
    if isinstance(annotation, ast.Subscript):
        return _expected_name(annotation.slice)
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _union_expected_name(annotation)

    name = _simple_annotation_name(annotation)
    if name is None:
        return None
    if name in _IGNORED_TYPE_NAMES:
        return None
    if not name or not name[0].isupper():
        return None
    return _to_snake(_trim_role_suffix(name))


def _union_expected_name(annotation: ast.BinOp) -> str | None:
    for side in (annotation.left, annotation.right):
        if _is_none_annotation(side):
            continue
        return _expected_name(side)
    return None


def _is_none_annotation(annotation: ast.expr) -> bool:
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return True
    return isinstance(annotation, ast.Name) and annotation.id == "None"


def _simple_annotation_name(annotation: ast.expr) -> str | None:
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Attribute):
        if _root_name(annotation) == "ast":
            return None
        return annotation.attr
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return annotation.value
    return None


def _trim_role_suffix(name: str) -> str:
    trimmed = name
    for suffix in _TRIM_SUFFIXES:
        if trimmed.endswith(suffix) and len(trimmed) > len(suffix):
            trimmed = trimmed[: -len(suffix)]
            break
    return trimmed


def _is_collection_annotation(annotation: ast.expr) -> bool:
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _is_collection_annotation(annotation.left) or _is_collection_annotation(
            annotation.right
        )
    if not isinstance(annotation, ast.Subscript):
        return False
    outer = _annotation_type_name(annotation.value)
    if outer in _COLLECTION_TYPES:
        return True
    if outer in _WRAPPER_TYPES:
        return _has_collection_annotation(annotation.slice)
    return False


def _has_collection_annotation(annotation: ast.expr) -> bool:
    if _is_collection_annotation(annotation):
        return True
    if isinstance(annotation, ast.Tuple):
        return any(_has_collection_annotation(elt) for elt in annotation.elts)
    return False


def _annotation_type_name(annotation: ast.expr) -> str | None:
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Attribute):
        return annotation.attr
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return annotation.value
    return None


def _root_name(annotation: ast.Attribute) -> str | None:
    value = annotation.value
    while isinstance(value, ast.Attribute):
        value = value.value
    if isinstance(value, ast.Name):
        return value.id
    return None


def _has_plural_match(param_name: str, expected: str) -> bool:
    if param_name in _plural_name_candidates(expected):
        return True
    param_tokens = set(lower_tokens(param_name))
    return bool(param_tokens & _plural_name_candidates(expected))


def _plural_name_candidates(expected: str) -> frozenset[str]:
    candidates = {_pluralize(expected)}
    tokens = expected.split("_")
    if len(tokens) > 1:
        candidates.add(_pluralize(tokens[0]))
        candidates.add(_pluralize(tokens[-1]))
    return frozenset(candidates)


def _suggested_parameter_name(annotation: ast.expr | None, expected: str) -> str:
    if annotation is None or not _is_collection_annotation(annotation):
        return expected
    return _collection_parameter_name(expected)


def _collection_parameter_name(expected: str) -> str:
    tokens = expected.split("_")
    if len(tokens) > 1 and tokens[-1] in _HEAD_NOUN_SUFFIX_TOKENS:
        return _pluralize(tokens[0])
    tokens[-1] = _pluralize(tokens[-1])
    return "_".join(tokens)


def _pluralize(name: str) -> str:
    if name.endswith("y") and (len(name) < 2 or name[-2] not in "aeiou"):
        return f"{name[:-1]}ies"
    if name.endswith(("s", "x", "z", "ch", "sh")):
        return f"{name}es"
    return f"{name}s"


def _to_snake(camel: str) -> str:
    """Convert ``UserService`` to ``user_service`` / ``HTTPServer`` to ``http_server``."""
    out = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", camel)
    out = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", out)
    return out.lower()


def _has_shared_token(param_name: str, expected: str) -> bool:
    """True when *param_name* shares a semantic token with *expected*.

    Both inputs are tokenised; if the lowercase token set of *param_name*
    intersects the lowercase token set of *expected*, the param is considered
    semantically related to the type. Single-letter tokens are excluded
    (they're too common - `x`, `n`).
    """
    param_tokens = {t for t in lower_tokens(param_name) if len(t) > 1}
    expected_tokens = {t for t in expected.split("_") if len(t) > 1}
    return bool(param_tokens & expected_tokens)


def _has_shared_path_role(param_name: str, expected: str) -> bool:
    return expected == "path" and bool(set(lower_tokens(param_name)) & _PATH_ROLE_TOKENS)


def _is_test_file(display_path: str) -> bool:
    normalized = display_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("tests/") or "/tests/" in normalized:
        return True
    return "/" not in normalized and name.startswith("test_") and name.endswith(".py")
