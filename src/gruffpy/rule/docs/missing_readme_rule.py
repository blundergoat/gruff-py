"""``docs.missing-readme`` — project root has no README.md / .rst / extensionless README.

Project-scoped: every unit emits the same finding when the README is absent;
the registry's deduplication collapses them to one. Net behaviour is "at most
one missing-readme finding per run" without per-instance run-state that would
leak across reused registries.
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

_README_CANDIDATES: tuple[str, ...] = (
    "README.md",
    "README.rst",
    "README.txt",
    "README",
)


class MissingReadmeRule(Rule):
    ID = "docs.missing-readme"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Missing README",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        root = context.project_root
        if _has_readme(root):
            return []

        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message="Project root has no README (README.md, README.rst, or README).",
                file_path=str(Path(root) / "README.md"),
                line=None,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    "Add a README.md at the project root describing the project's purpose, "
                    "install instructions, and a usage example."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={"projectRoot": root},
            ),
        ]


def _has_readme(project_root: str) -> bool:
    root_path = Path(project_root)
    return any((root_path / name).exists() for name in _README_CANDIDATES)
