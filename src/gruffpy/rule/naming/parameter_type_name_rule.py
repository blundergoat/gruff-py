"""Parameter name doesn't match its type-hint role.

When a parameter is annotated ``repo: Repository``, the conventional name is
``repository`` — the short ``repo`` form makes calls less self-documenting.

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

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule

_TRIM_SUFFIXES: tuple[str, ...] = (
    "Service",
    "Repository",
    "Protocol",
    "ABC",
    "Type",
    "Adapter",
    "Provider",
)
_DEFAULT_IGNORED: tuple[str, ...] = ("id", "ctx", "url", "ip", "io", "ui", "fn")
_IGNORED_TYPE_NAMES: frozenset[str] = frozenset({"Any"})
_PATH_ROLE_TOKENS: frozenset[str] = frozenset({"path", "root", "file", "dir", "directory"})
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


class ParameterTypeNameRule(Rule):
    ID = "naming.parameter-type-name"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Parameter type name",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"ignoredParameterNames": list(_DEFAULT_IGNORED)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        if _is_test_file(unit.file.display_path):
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        configured = settings.options.get("ignoredParameterNames", list(_DEFAULT_IGNORED))
        if not isinstance(configured, list) or not all(isinstance(s, str) for s in configured):
            configured = list(_DEFAULT_IGNORED)
        ignored = frozenset(configured)

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for arg in (
                list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
            ):
                if arg.annotation is None:
                    continue
                if arg.arg.startswith("_") or arg.arg in ignored or arg.arg in {"self", "cls"}:
                    continue
                expected = _expected_name(arg.annotation)
                if expected is None:
                    continue
                if arg.arg == expected:
                    continue
                # Accept the short form when the parameter name is a prefix
                # of the expected canonical form (e.g. ``repo`` of ``repository``).
                if expected.startswith(arg.arg) and len(arg.arg) >= 2:
                    continue
                if _is_collection_annotation(arg.annotation) and _matches_plural(arg.arg, expected):
                    continue
                # Accept when the param name shares at least one token with
                # the type name — ``unit: AnalysisUnit`` (param `unit` shares
                # `unit` with `analysis_unit`) is fine. Only fire when the
                # param name has NO semantic overlap with the type.
                if _shares_token(arg.arg, expected):
                    continue
                if _shares_path_role(arg.arg, expected):
                    continue
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Parameter {arg.arg!r} annotated as a complex type; "
                            f"prefer the canonical name ``{expected}``."
                        ),
                        file_path=unit.file.display_path,
                        line=arg.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=arg.lineno,
                        symbol=arg.arg,
                        remediation=f"Rename ``{arg.arg}`` to ``{expected}``.",
                        secondary_pillars=definition.secondary_pillars,
                        metadata={
                            "parameter": arg.arg,
                            "expected": expected,
                        },
                    ),
                )
        return findings


def _expected_name(annotation: ast.expr) -> str | None:
    """Return the canonical snake_case name for *annotation*, or None when the
    annotation is not a single Title-cased class-like name."""
    if isinstance(annotation, ast.Subscript):
        # Unwrap one level: Optional[Foo] -> Foo, list[Foo] -> Foo
        return _expected_name(annotation.slice)
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        # T | None -> T
        for side in (annotation.left, annotation.right):
            if isinstance(side, ast.Constant) and side.value is None:
                continue
            if isinstance(side, ast.Name) and side.id == "None" or side is None:
                continue
            return _expected_name(side)
    if isinstance(annotation, ast.Name):
        name = annotation.id
    elif isinstance(annotation, ast.Attribute):
        # x.y.Foo -> Foo
        if _root_name(annotation) == "ast":
            return None
        name = annotation.attr
    elif isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        name = annotation.value
    else:
        return None
    if name in _IGNORED_TYPE_NAMES:
        return None
    if not name or not name[0].isupper():
        return None
    # Trim trailing role suffix
    trimmed = name
    for suffix in _TRIM_SUFFIXES:
        if trimmed.endswith(suffix) and len(trimmed) > len(suffix):
            trimmed = trimmed[: -len(suffix)]
            break
    return _to_snake(trimmed)


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
        return _contains_collection(annotation.slice)
    return False


def _contains_collection(annotation: ast.expr) -> bool:
    if _is_collection_annotation(annotation):
        return True
    if isinstance(annotation, ast.Tuple):
        return any(_contains_collection(elt) for elt in annotation.elts)
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


def _matches_plural(param_name: str, expected: str) -> bool:
    if param_name == _pluralize(expected):
        return True
    param_tokens = set(lower_tokens(param_name))
    expected_tokens = expected.split("_")
    return _pluralize(expected_tokens[-1]) in param_tokens


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


def _shares_token(param_name: str, expected: str) -> bool:
    """True when *param_name* shares a semantic token with *expected*.

    Both inputs are tokenised; if the lowercase token set of *param_name*
    intersects the lowercase token set of *expected*, the param is considered
    semantically related to the type. Single-letter tokens are excluded
    (they're too common — `x`, `n`).
    """
    param_tokens = {t for t in lower_tokens(param_name) if len(t) > 1}
    expected_tokens = {t for t in expected.split("_") if len(t) > 1}
    return bool(param_tokens & expected_tokens)


def _shares_path_role(param_name: str, expected: str) -> bool:
    return expected == "path" and bool(set(lower_tokens(param_name)) & _PATH_ROLE_TOKENS)


def _is_test_file(display_path: str) -> bool:
    normalized = display_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("tests/") or "/tests/" in normalized:
        return True
    return "/" not in normalized and name.startswith("test_") and name.endswith(".py")
