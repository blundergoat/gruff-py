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
from pathlib import Path

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


class ModuleNameMismatchRule(Rule):
    ID = "naming.module-name-mismatch"

    def definition(self) -> RuleDefinition:
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
        if not isinstance(unit.tree, ast.Module):
            return []
        filename = Path(unit.file.display_path).name
        if filename == "__init__.py" or not filename.endswith(".py"):
            return []
        stem = filename[:-3]

        public_classes = [
            node
            for node in unit.tree.body
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_")
        ]
        if len(public_classes) != 1:
            return []
        cls = public_classes[0]
        class_token_variants = _class_token_variants(cls.name)
        expected_stem = "_".join(class_token_variants[0])
        if expected_stem == stem:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        conventional_module_names = _conventional_module_names(
            settings.options.get("conventionalModuleNames")
        )
        if _is_class_name_matching_import_path(class_token_variants, unit.file.display_path):
            return []
        if _is_conventional_module_match(
            stem,
            conventional_module_names,
            class_token_variants,
            unit.file.display_path,
        ):
            return []

        return [
            Finding(
                rule_id=definition.id,
                message=(
                    f"Single-class module {filename!r} should be named "
                    f"``{expected_stem}.py`` to match the class {cls.name!r}."
                ),
                file_path=unit.file.display_path,
                line=cls.lineno,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=cls.end_lineno,
                symbol=cls.name,
                remediation=f"Rename {filename!r} to ``{expected_stem}.py``.",
                secondary_pillars=definition.secondary_pillars,
                metadata={
                    "expectedFilename": f"{expected_stem}.py",
                    "actualFilename": filename,
                    "class": cls.name,
                },
            )
        ]


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
