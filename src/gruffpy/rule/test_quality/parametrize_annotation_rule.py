"""``test-quality.parametrize-annotation`` — ``@parametrize`` without an ``ids=`` argument.

Without ``ids=``, pytest names cases by their repr — opaque output when a case
fails. The rule fires when more than two cases are provided without an ``ids``
labelling.
"""

import ast
from dataclasses import dataclass

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_node_helper import call_keyword, call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class _ParametrizeWithoutIds:
    fn: FunctionNode
    decorator: ast.Call
    case_count: int


class ParametrizeAnnotationRule(Rule):
    ID = "test-quality.parametrize-annotation"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Parametrize without `ids`",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 2},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        min_cases = settings.numeric_threshold("warning")
        return [
            _parametrize_without_ids_finding(unit, definition, candidate)
            for candidate in _parametrize_without_ids(unit, min_cases)
        ]


def _parametrize_without_ids(
    unit: AnalysisUnit,
    min_cases: int | float,
) -> list[_ParametrizeWithoutIds]:
    findings: list[_ParametrizeWithoutIds] = []
    for fn, _scope in test_functions(unit):
        for decorator in fn.decorator_list:
            candidate = _parametrize_candidate(fn, decorator, min_cases)
            if candidate is not None:
                findings.append(candidate)
    return findings


def _parametrize_candidate(
    fn: FunctionNode,
    decorator: ast.expr,
    min_cases: int | float,
) -> _ParametrizeWithoutIds | None:
    if not isinstance(decorator, ast.Call):
        return None
    target = call_target_name(decorator)
    if target is None or not target.endswith("parametrize") or len(decorator.args) < 2:
        return None
    cases = decorator.args[1]
    case_count = len(cases.elts) if isinstance(cases, ast.List | ast.Tuple) else 0
    if case_count <= min_cases or call_keyword(decorator, "ids") is not None:
        return None
    return _ParametrizeWithoutIds(fn=fn, decorator=decorator, case_count=case_count)


def _parametrize_without_ids_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _ParametrizeWithoutIds,
) -> Finding:
    symbol = qualified_symbol(candidate.fn, parent_chain(candidate.fn))
    return Finding(
        rule_id=definition.id,
        message=(
            f"Test {symbol!r} has @parametrize with {candidate.case_count} cases but no "
            f"`ids=` for human-readable case names."
        ),
        file_path=unit.file.display_path,
        line=candidate.decorator.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=candidate.decorator.end_lineno,
        symbol=symbol,
        remediation=(
            "Add `ids=['case-a', 'case-b', ...]` so failed cases are "
            "identifiable in the report."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"caseCount": candidate.case_count},
    )
