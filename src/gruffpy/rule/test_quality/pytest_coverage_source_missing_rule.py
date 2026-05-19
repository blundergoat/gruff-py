"""``test-quality.pytest-coverage-source-missing`` — ``[tool.coverage.run].source`` empty or absent.

Without an explicit source list, coverage measurement is implicit and
misses modules that aren't imported during the suite. The rule wants
``source = ["my_package"]`` declared.
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


class PytestCoverageSourceMissingRule(Rule):
    ID = "test-quality.pytest-coverage-source-missing"

    def definition(self) -> RuleDefinition:
        """Describe the coverage-source-missing rule as a medium-confidence advisory.

        Medium confidence because some projects intentionally rely on
        ``--cov=<pkg>`` CLI flags or other tools; the rule encourages
        declarative configuration but can't prove the user isn't covered by
        another mechanism.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Coverage source missing",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit a pyproject-anchored finding when ``[tool.coverage.run].source`` is empty or absent.

        Per-unit: each test-bearing unit contributes one finding (downstream
        dedup collapses the duplicates that share a fingerprint). Skipped
        when the unit has no test functions or when no pytest config block
        exists in ``pyproject.toml``.

        Args:
            unit: Parsed source file used to detect test presence.
            context: Rule execution context supplying the ``project_root``
                used to locate pyproject.toml.

        Returns:
            One pyproject.toml-anchored finding when coverage source is
            absent (and the unit has tests), otherwise empty.
        """
        if unit.tree is None or not any(True for _ in test_functions(unit)):
            return []
        config = read_pytest_config(context.project_root)
        if not config.is_present or config.has_coverage_source():
            return []
        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message="Coverage `source` is empty or absent — coverage may be incomplete.",
                file_path=str(Path(context.project_root) / "pyproject.toml"),
                line=None,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    'Add `source = ["<package>"]` to `[tool.coverage.run]` so coverage '
                    "measures every module, even those not imported by the suite."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={"projectRoot": context.project_root},
            ),
        ]
