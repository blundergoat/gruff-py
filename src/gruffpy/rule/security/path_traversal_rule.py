"""``security.path-traversal`` - filesystem sinks reached by user-controlled paths.

When user-controlled input flows into a file-API call (``open``,
``shutil.copyfile``, ``pathlib.Path(...).read_text()``), the path can
contain ``../`` traversal sequences, absolute paths, or symlink targets
that escape the intended base directory.

The rule uses the bounded intra-procedural taint helper
(``_security_taint_helper.py``) per ADR-017. A finding fires when the
path argument of a known file-API sink is tainted by a recognised request
source in the same function.

Recognised sinks (file gated to web-framework imports):

- ``open(<path>, ...)`` - first argument.
- ``os.remove(<path>)``, ``os.unlink(<path>)`` - first argument.
- ``shutil.copyfile/copy/copy2/move/rename(<src>, ...)`` - source argument.
- ``pathlib.Path(<path>).read_text/read_bytes/write_text/write_bytes/open(...)``
  - chained shape; the rule inspects the path passed to ``Path(...)``.

Recognised sanitisers (their return values are treated as untainted):

- ``secure_filename`` (Werkzeug) - strips ``..``, absolute prefixes, and
  separators.
- ``os.path.basename`` - strips any directory component.

The assigned-then-called form (``p = Path(tainted); p.read_text()``)
requires Path-aware identifier propagation and is out of scope for v1.
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
from gruffpy.rule.security._security_node_helper import call_target_name, frameworks_in_use
from gruffpy.rule.security._security_taint_helper import TaintAnalyser

_FRAMEWORK_GATE: frozenset[str] = frozenset({"flask", "django", "fastapi"})
_SHUTIL_SOURCE_LEAVES: frozenset[str] = frozenset({"copyfile", "copy", "copy2", "move", "rename"})
_OS_REMOVE_LEAVES: frozenset[str] = frozenset({"remove", "unlink"})
_PATH_READ_WRITE_LEAVES: frozenset[str] = frozenset(
    {"read_text", "read_bytes", "write_text", "write_bytes", "open"}
)
_PATH_CONSTRUCTORS: frozenset[str] = frozenset({"Path", "PurePath", "PosixPath", "PurePosixPath"})
_PATH_TRAVERSAL_SANITISERS: frozenset[str] = frozenset({"secure_filename", "basename"})
_SOURCE_NEEDLES: tuple[str, ...] = (
    "open",
    "Path",
    "shutil",
    "read_text",
    "write_text",
    "read_bytes",
    "write_bytes",
    "remove",
    "unlink",
    "copyfile",
    "move",
    "rename",
)
_REMEDIATION = (
    "Run user-controlled paths through `werkzeug.utils.secure_filename()` "
    "or `os.path.basename()` to strip traversal sequences. For absolute "
    "lookups, resolve with `os.path.realpath()` and verify the result is "
    "under an expected base directory before opening."
)


class PathTraversalRule(Rule):
    """Detect filesystem sinks whose path argument is tainted."""

    ID = "security.path-traversal"

    def definition(self) -> RuleDefinition:
        """Describe the path-traversal rule as a high-confidence ERROR.

        ERROR severity because path traversal grants read/write access to
        files outside the intended directory, including configuration,
        credentials, and source; high confidence because the matched
        sinks + intra-procedural taint pinpoint the path argument
        without ambiguity.

        Returns:
            Definition for the path-traversal rule under the security
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Path traversal",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag file-API sinks reached by tainted path arguments.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per call site whose path argument is tainted.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        if not (frameworks_in_use(unit.tree) & _FRAMEWORK_GATE):
            return []
        taint_map = TaintAnalyser(_PATH_TRAVERSAL_SANITISERS).analyse_tree(unit.tree)
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            path_arg = _path_sink_argument(node)
            if path_arg is None or not taint_map.is_tainted(path_arg):
                continue
            findings.append(_build_finding(definition, unit, node))
        return findings


def _path_sink_argument(call: ast.Call) -> ast.expr | None:
    if _is_path_chained_sink(call):
        assert isinstance(call.func, ast.Attribute)  # noqa: S101  # narrowed by helper
        receiver = call.func.value
        if isinstance(receiver, ast.Call) and receiver.args:
            return receiver.args[0]
        return None
    target = call_target_name(call)
    if target is None or not call.args:
        return None
    parts = target.split(".")
    leaf = parts[-1]
    if leaf == "open" and len(parts) == 1:
        return call.args[0]
    if leaf in _OS_REMOVE_LEAVES and parts[0] == "os":
        return call.args[0]
    if leaf in _SHUTIL_SOURCE_LEAVES and parts[0] == "shutil":
        return call.args[0]
    return None


def _is_path_chained_sink(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr not in _PATH_READ_WRITE_LEAVES:
        return False
    receiver = call.func.value
    if not isinstance(receiver, ast.Call):
        return False
    receiver_target = call_target_name(receiver)
    if receiver_target is None:
        return False
    return receiver_target.split(".")[-1] in _PATH_CONSTRUCTORS


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
) -> Finding:
    target = call_target_name(call) or "?"
    return Finding(
        rule_id=definition.id,
        message=(f"`{target}(...)` reads/writes a user-controlled path - path traversal risk."),
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
                source_label="user-controlled-path",
                sink_label="filesystem",
            ),
        },
    )
