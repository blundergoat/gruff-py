"""``security.github-actions-unpinned-action`` - workflow step pins an action to a mutable ref.

Fires on GitHub Actions workflow files (``.github/workflows/*.yml`` /
``*.yaml``) whose ``uses:`` steps reference a third-party action by a movable
tag or branch (``some-org/action@v4``, ``@main``) instead of a full-length
commit SHA. A moved tag silently swaps the executed code, so SHA-pinning is
the only review-verifiable supply-chain control. GitHub-owned ``actions/*`` and
``github/*`` orgs, local ``./`` actions, and ``docker://`` references are
exempt.
"""

import re

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import SourceTextRule
from gruffpy.rule.security._security_metadata import finding_security_metadata

_USES_RE = re.compile(r"^\s*-?\s*uses:\s*[\"']?(?P<spec>[^\"'\s#]+)[\"']?", re.MULTILINE)
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_FIRST_PARTY_ORGS: frozenset[str] = frozenset({"actions", "github"})


class GithubActionsUnpinnedActionRule(SourceTextRule):
    """Flag workflow `uses:` steps pinned to a mutable tag/branch instead of a commit SHA."""

    ID = "security.github-actions-unpinned-action"

    def definition(self) -> RuleDefinition:
        """Describe the unpinned-action rule as a high-confidence posture warning.

        High confidence because "the ref is not a 40-char SHA" is an exact
        textual test, not a heuristic; warning severity because an unpinned
        action is a supply-chain posture smell rather than an active exploit.

        Returns:
            Definition for the github-actions-unpinned-action rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unpinned GitHub Actions reference",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag each ``uses:`` step that pins a third-party action to a movable ref.

        Only runs on files under ``.github/workflows/`` ending in
        ``.yml``/``.yaml``. Local (``./``), ``docker://``, and GitHub-owned
        (``actions/*``, ``github/*``) references are skipped, as are actions
        already pinned to a full 40-character commit SHA.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unpinned third-party ``uses:`` reference.
        """
        if not _is_workflow_file(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for match in _USES_RE.finditer(unit.source):
            action = _unpinned_action(match.group("spec"))
            if action is None:
                continue
            path, ref = action
            line = unit.source.count("\n", 0, match.start("spec")) + 1
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"GitHub Actions step uses `{path}@{ref}` - a movable tag/branch. "
                        "Pin third-party actions to a full-length commit SHA so a moved "
                        "tag cannot swap the executed code."
                    ),
                    file_path=unit.file.display_path,
                    line=line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Replace the tag/branch with the full 40-character commit SHA it "
                        "currently points at, keeping the version in a trailing comment, "
                        "e.g. `uses: owner/repo@<sha>  # v4.1.0`."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "action": path,
                        "ref": ref,
                        **finding_security_metadata(
                            definition.id,
                            source_label="github-actions-workflow",
                            sink_label="third-party-action",
                        ),
                    },
                ),
            )
        return findings


def _is_workflow_file(display_path: str) -> bool:
    normalised = display_path.replace("\\", "/")
    return ".github/workflows/" in normalised and normalised.endswith((".yml", ".yaml"))


def _unpinned_action(spec: str) -> tuple[str, str] | None:
    """Return ``(path, ref)`` when *spec* is an unpinned third-party action, else ``None``."""
    if spec.startswith((".", "/")) or spec.startswith("docker://"):
        return None  # Local or container action - different supply chain.
    if "@" not in spec:
        return None  # No ref to evaluate.
    path, _, ref = spec.partition("@")
    if "/" not in path:
        return None  # Not an owner/repo action reference.
    if path.split("/", 1)[0] in _FIRST_PARTY_ORGS:
        return None  # GitHub-owned action - treated as first-party.
    if _SHA_RE.match(ref):
        return None  # Already pinned to a full commit SHA.
    return path, ref
