"""``test-quality.parametrize-annotation`` — ``@parametrize`` without an ``ids=`` argument.

Without ``ids=``, pytest names cases by their repr — opaque output when a case
fails. The rule fires when more than two cases are provided without an ``ids``
labelling.
"""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.security._security_node_helper import call_keyword, call_target_name
from gruff.rule.size._lines import parent_chain, qualified_symbol
from gruff.rule.test_quality._test_quality_node_helper import test_functions


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
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for decorator in fn.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                target = call_target_name(decorator)
                if target is None or not target.endswith("parametrize"):
                    continue
                if len(decorator.args) < 2:
                    continue
                cases = decorator.args[1]
                case_count = len(cases.elts) if isinstance(cases, ast.List | ast.Tuple) else 0
                if case_count <= min_cases:
                    continue
                if call_keyword(decorator, "ids") is not None:
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Test {symbol!r} has @parametrize with {case_count} cases but no "
                            f"`ids=` for human-readable case names."
                        ),
                        file_path=unit.file.display_path,
                        line=decorator.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=decorator.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Add `ids=['case-a', 'case-b', ...]` so failed cases are "
                            "identifiable in the report."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"caseCount": case_count},
                    ),
                )
        return findings
