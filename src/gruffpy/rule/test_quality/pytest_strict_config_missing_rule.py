"""``test-quality.pytest-strict-config-missing`` — pyproject lacks strict pytest flags.

Fires at most once per analyse run, gated on at least one test-shaped unit
being in scope (no point flagging configuration on a non-test analyse).
"""

from pathlib import Path

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.test_quality._pytest_config import read_pytest_config
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class PytestStrictConfigMissingRule(Rule):
    ID = "test-quality.pytest-strict-config-missing"

    def definition(self) -> RuleDefinition:
        """Describe the pytest-strict-config-missing rule as a medium-confidence advisory.

        Medium confidence because while ``--strict-config``/
        ``--strict-markers`` is a strong default, some projects deliberately
        accept unknown markers (plugin compatibility shims).

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Pytest strict-config missing",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit a pyproject-anchored finding when pytest lacks ``--strict-config`` or markers.

        Gated on at least one test-shaped function being in the analysed
        unit and on a pytest config block being present; without strict
        flags, unknown options and markers silently pass.

        Args:
            unit: Parsed source file used to detect test presence.
            context: Rule execution context supplying the ``project_root``
                used to locate pyproject.toml.

        Returns:
            One pyproject.toml-anchored finding when strict flags are
            absent, otherwise empty.
        """
        if not _has_tests(unit):
            return []
        config = read_pytest_config(context.project_root)
        if not config.is_present or config.has_strict_config():
            return []
        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message=(
                    "Pytest config missing strict flags (`--strict-config` or `--strict-markers`)."
                ),
                file_path=str(Path(context.project_root) / "pyproject.toml"),
                line=None,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    'Add `addopts = "--strict-config --strict-markers"` to '
                    "`[tool.pytest.ini_options]` so unknown options and markers fail fast."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={"projectRoot": context.project_root},
            ),
        ]


def _has_tests(unit: AnalysisUnit) -> bool:
    if unit.tree is None:
        return False
    return any(True for _fn, _scope in test_functions(unit))
