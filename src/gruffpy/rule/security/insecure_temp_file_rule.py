"""``security.insecure-temp-file`` - race-prone temp-file APIs and hardcoded /tmp paths.

Two unsafe patterns:

- ``tempfile.mktemp()`` - returns a path without creating the file, leaving
  a TOCTOU window in which an attacker can pre-create the path (often as a
  symlink). The replacement is ``tempfile.mkstemp()`` /
  ``tempfile.NamedTemporaryFile()``, which atomically create the file.
- Hardcoded ``/tmp/`` or ``/var/tmp/`` string literals passed to file APIs
  (``open``, ``Path``, ``shutil.copyfile`` / ``copy`` / ``move``,
  ``os.remove`` / ``unlink``). ``/tmp`` is world-writeable; predictable
  filenames there enable symlink and race attacks. The replacement is
  ``tempfile.gettempdir()`` joined with a generated suffix, or one of the
  atomic temp-file APIs above.
"""

import ast

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

_MKTEMP_TARGETS: frozenset[str] = frozenset({"tempfile.mktemp", "mktemp"})
_TMP_PREFIXES: tuple[str, ...] = ("/tmp/", "/var/tmp/")
_FILE_API_LEAVES: frozenset[str] = frozenset(
    {"open", "copyfile", "copy", "copy2", "move", "remove", "unlink", "rename"}
)
_PATH_CONSTRUCTORS: frozenset[str] = frozenset({"Path", "PurePath", "PosixPath", "PurePosixPath"})
_SOURCE_NEEDLES: tuple[str, ...] = ("mktemp", "/tmp/", "/var/tmp/")
_MKTEMP_REMEDIATION = (
    "Use `tempfile.NamedTemporaryFile()` or `tempfile.mkstemp()` - both "
    "atomically create the file, eliminating the TOCTOU window that "
    "`mktemp()` leaves open."
)
_HARDCODED_TMP_REMEDIATION = (
    "Join `tempfile.gettempdir()` with a generated suffix instead of "
    "hardcoding `/tmp/...`. Predictable filenames under `/tmp` enable "
    "symlink and race attacks on a world-writeable directory."
)


class InsecureTempFileRule(Rule):
    """Detect tempfile.mktemp() and hardcoded /tmp/ paths in file-API calls."""

    ID = "security.insecure-temp-file"

    def definition(self) -> RuleDefinition:
        """Describe the insecure-temp-file rule as a medium-confidence WARNING.

        WARNING severity because the TOCTOU window only matters on shared
        hosts (less common in containerised deploys); medium confidence
        because the matched shapes are explicit but legitimate uses exist
        (debug scripts writing well-known paths).

        Returns:
            Definition for the insecure-temp-file rule under the security
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Insecure temporary file",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tempfile.mktemp() and file-API calls with hardcoded /tmp prefixes.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per mktemp call or per hardcoded /tmp path passed
            to a file API.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            finding = _finding_for_call(unit, definition, node)
            if finding is not None:
                findings.append(finding)
        return findings


def _finding_for_call(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    call: ast.Call,
) -> Finding | None:
    target = call_target_name(call)
    if target in _MKTEMP_TARGETS:
        return _build_mktemp_finding(definition, unit, call)
    leaf = target.split(".")[-1] if target else None
    if leaf in _FILE_API_LEAVES or leaf in _PATH_CONSTRUCTORS:
        prefix_match = _hardcoded_temp_argument(call)
        if prefix_match is not None:
            return _build_temp_path_finding(definition, unit, call, leaf or "?", prefix_match)
    return None


def _hardcoded_temp_argument(call: ast.Call) -> str | None:
    for arg in call.args:
        if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
            continue
        if arg.value.startswith(_TMP_PREFIXES):
            return arg.value
    return None


def _build_mktemp_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            "`tempfile.mktemp()` returns a path without creating the file - TOCTOU race risk."
        ),
        file_path=unit.file.display_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation=_MKTEMP_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "shape": "mktemp",
            **finding_security_metadata(
                definition.id,
                source_label="filesystem",
                sink_label="temp-file-creation",
            ),
        },
    )


def _build_temp_path_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    leaf: str,
    matched_literal: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"`{leaf}('{matched_literal}'...)` uses a hardcoded world-writeable "
            "tmp path - symlink / race risk."
        ),
        file_path=unit.file.display_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation=_HARDCODED_TMP_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "shape": "hardcoded-tmp-path",
            "path": matched_literal,
            **finding_security_metadata(
                definition.id,
                source_label="filesystem",
                sink_label="temp-file-path",
            ),
        },
    )
