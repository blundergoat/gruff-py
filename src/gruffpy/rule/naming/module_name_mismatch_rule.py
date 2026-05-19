"""Single-class module whose class name doesn't match the snake_cased filename.

Single-class module = exactly one top-level non-private class symbol; adjacent
``_helpers``-style private symbols are ignored. The expected filename is the
snake_case form of the class name.

Examples:

- ``class UserService:`` in ``users.py`` -> expected ``user_service.py``.
- ``class HTTPServer:`` in ``server.py`` -> expected ``http_server.py``.

Skip ``__init__.py`` (intentionally re-exports many classes).
"""

import ast
from dataclasses import dataclass
from pathlib import Path

from gruffpy.config.rule_settings import RuleSettings
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

_ROLE_SUFFIX_TOKENS: frozenset[str] = frozenset(
    {
        "adapter",
        "error",
        "matcher",
        "protocol",
        "provider",
        "repository",
        "service",
        "type",
    }
)
_CONVENTIONAL_MODULE_NAMES: tuple[str, ...] = (
    "constants",
    "exceptions",
    "helpers",
    "protocols",
    "types",
)


@dataclass(frozen=True, slots=True)
class _MismatchCandidate:
    """Intermediate state for a possible module/class name mismatch."""

    filename: str
    stem: str
    cls: ast.ClassDef
    class_token_variants: list[list[str]]
    expected_stem: str


class ModuleNameMismatchRule(Rule):
    """Detect single-class modules whose filename does not snake_case-match the class name."""

    ID = "naming.module-name-mismatch"

    def definition(self) -> RuleDefinition:
        """Describe the module-name-mismatch rule with a configurable module list.

        The ``conventionalModuleNames`` option lists filenames that may host
        a different-named class without firing (``constants.py``,
        ``exceptions.py``, ``helpers.py``, ``protocols.py``, ``types.py``).

        Returns:
            Definition for the module-name-mismatch rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Module name mismatch",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"conventionalModuleNames": list(_CONVENTIONAL_MODULE_NAMES)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag single-public-class modules whose filename doesn't match the class.

        Skipped when: the file is ``__init__.py``; the import path already
        carries the class's tokens (``config/loader.py`` containing
        ``class ConfigLoader`` is fine — ``config`` plus ``loader`` cover
        the class); or the file is a conventional bucket (``constants.py``,
        ``exceptions.py``, etc.) sharing any token with the class.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the
                ``conventionalModuleNames`` option.

        Returns:
            Empty list, or a single finding pointing at the mismatched class.
        """
        candidate = _mismatch_candidate(unit)
        if candidate is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        if _is_accepted_mismatch_candidate(candidate, settings, unit.file.display_path):
            return []
        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"Single-class module {candidate.filename!r} should be named "
                    f"``{candidate.expected_stem}.py`` to match the class "
                    f"{candidate.cls.name!r}."
                ),
                file_path=unit.file.display_path,
                line=candidate.cls.lineno,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=candidate.cls.end_lineno,
                symbol=candidate.cls.name,
                remediation=(f"Rename {candidate.filename!r} to ``{candidate.expected_stem}.py``."),
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "expectedFilename": f"{candidate.expected_stem}.py",
                    "actualFilename": candidate.filename,
                    "class": candidate.cls.name,
                },
            )
        ]


def _mismatch_candidate(unit: AnalysisUnit) -> _MismatchCandidate | None:
    if not isinstance(unit.tree, ast.Module):
        return None
    filename = Path(unit.file.display_path).name
    if _is_skipped_filename(filename):
        return None

    cls = _single_public_class(unit.tree)
    if cls is None:
        return None

    class_token_variants = _class_token_variants(cls.name)
    expected_stem = "_".join(class_token_variants[0])
    stem = filename[:-3]
    if expected_stem == stem:
        return None
    return _MismatchCandidate(
        filename=filename,
        stem=stem,
        cls=cls,
        class_token_variants=class_token_variants,
        expected_stem=expected_stem,
    )


def _is_skipped_filename(filename: str) -> bool:
    return filename == "__init__.py" or not filename.endswith(".py")


def _single_public_class(tree: ast.Module) -> ast.ClassDef | None:
    public_classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and not node.name.startswith("_")
    ]
    if len(public_classes) != 1:
        return None
    return public_classes[0]


def _is_accepted_mismatch_candidate(
    candidate: _MismatchCandidate,
    settings: RuleSettings,
    display_path: str,
) -> bool:
    conventional_module_names = _conventional_module_names(
        settings.options.get("conventionalModuleNames")
    )
    return _is_class_name_matching_import_path(
        candidate.class_token_variants,
        display_path,
    ) or _is_conventional_module_match(
        candidate.stem,
        conventional_module_names,
        candidate.class_token_variants,
        display_path,
    )


def _class_token_variants(name: str) -> list[list[str]]:
    tokens = lower_tokens(name)
    variants = [_join_leading_initialisms(tokens)]
    if tokens not in variants:
        variants.append(tokens)
    trimmed = _trim_role_suffix(tokens)
    if trimmed != tokens:
        joined_trimmed = _join_leading_initialisms(trimmed)
        if joined_trimmed not in variants:
            variants.append(joined_trimmed)
        if trimmed not in variants:
            variants.append(trimmed)
    return variants


def _join_leading_initialisms(tokens: list[str]) -> list[str]:
    result: list[str] = []
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if len(token) == 1 and idx + 1 < len(tokens):
            result.append(f"{token}{tokens[idx + 1]}")
            idx += 2
            continue
        result.append(token)
        idx += 1
    return result


def _is_class_name_matching_import_path(
    class_token_variants: list[list[str]],
    display_path: str,
) -> bool:
    path_tokens = set(_path_tokens(display_path))
    return any(set(variant).issubset(path_tokens) for variant in class_token_variants)


def _path_tokens(display_path: str) -> list[str]:
    path = Path(display_path)
    parts = list(path.with_suffix("").parts)
    tokens: list[str] = []
    for part in parts:
        if part in {"", ".", "src", "gruffpy", "__init__"}:
            continue
        tokens.extend(lower_tokens(part))
    return tokens


def _trim_role_suffix(tokens: list[str]) -> list[str]:
    if len(tokens) > 1 and tokens[-1] in _ROLE_SUFFIX_TOKENS:
        return tokens[:-1]
    return tokens


def _conventional_module_names(configured: object) -> frozenset[str]:
    if not isinstance(configured, list) or not all(isinstance(name, str) for name in configured):
        return frozenset(_CONVENTIONAL_MODULE_NAMES)
    return frozenset(configured)


def _is_conventional_module_match(
    stem: str,
    conventional_module_names: frozenset[str],
    class_token_variants: list[list[str]],
    display_path: str,
) -> bool:
    if stem not in conventional_module_names:
        return False
    path_tokens = set(_path_tokens(display_path))
    return any(bool(set(variant) & path_tokens) for variant in class_token_variants)
