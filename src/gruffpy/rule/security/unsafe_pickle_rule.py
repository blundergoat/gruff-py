"""``security.unsafe-pickle`` — pickle deserialisation of non-literal input.

``pickle.loads(b'...')`` against a literal byte string is safe (well, as safe as
shipping a literal bytes object can be). ``pickle.loads(user_input)`` is the
canonical RCE vector. The rule fires when the first argument is not a literal.
Also covers ``cPickle`` (legacy), ``pickle.Unpickler(file).load()``, and
``dill.loads``.
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
from gruffpy.rule.security._security_node_helper import call_target_name

_UNSAFE_LOAD_TARGETS: frozenset[str] = frozenset(
    {
        "pickle.loads",
        "pickle.load",
        "cPickle.loads",
        "cPickle.load",
        "dill.loads",
        "dill.load",
    }
)


class UnsafePickleRule(Rule):
    ID = "security.unsafe-pickle"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Unsafe pickle deserialisation",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            target = call_target_name(node)
            label = _unsafe_pickle_label(node, target)
            if label is None:
                continue
            findings.append(_build_finding(definition, unit, node, label))
        return findings


def _unsafe_pickle_label(call: ast.Call, target: str | None) -> str | None:
    if (
        target is not None
        and target in _UNSAFE_LOAD_TARGETS
        and not _first_arg_is_safe_literal(call)
    ):
        return target
    return _unpickler_load_label(call)


def _first_arg_is_safe_literal(call: ast.Call) -> bool:
    if not call.args:
        return False
    first = call.args[0]
    return isinstance(first, ast.Constant) and isinstance(first.value, bytes | str)


def _unpickler_load_label(call: ast.Call) -> str | None:
    """Return ``pickle.Unpickler.load`` (or cPickle/dill variant) for the chained pattern."""
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr != "load":
        return None
    receiver = func.value
    if not isinstance(receiver, ast.Call):
        return None
    receiver_target = call_target_name(receiver)
    if receiver_target not in {
        "pickle.Unpickler",
        "cPickle.Unpickler",
        "dill.Unpickler",
    }:
        return None
    return f"{receiver_target}.load"


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    target: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=f"`{target}(...)` deserialises a non-literal input — pickle is a known RCE vector.",
        file_path=unit.file.display_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation=(
            "Use a structured format (JSON, msgpack with strict schema, "
            "protobuf) for untrusted data. Reserve pickle for trusted internal IPC."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"target": target},
    )
