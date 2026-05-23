"""``docs.ignore-directive-reason`` - suppression comments need a reason."""

import re
from dataclasses import dataclass

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._comment_scanner import SourceComment, scan_comments
from gruffpy.rule.rule import Rule

_DIRECTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?P<directive>noqa(?:\s*:\s*[A-Z0-9]+(?:[,\s]+[A-Z0-9]+)*)?)"
        r"(?=\s*(?:#|--|-|:|$))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<directive>type:\s*ignore(?:\[[^\]]+\])?)(?=\s*(?:#|--|-|:|$))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<directive>pyright:\s*ignore(?:\[[^\]]+\])?)(?=\s*(?:#|--|-|:|$))",
        re.IGNORECASE,
    ),
    re.compile(r"(?P<directive>pragma:\s*no\s+cover)(?=\s*(?:#|--|-|:|$))", re.IGNORECASE),
    re.compile(
        r"(?P<directive>gruff:\s*disable(?:-next|-file)?\s*=\s*[A-Za-z0-9_.-]+"
        r"(?:\s*,\s*[A-Za-z0-9_.-]+)*)(?=\s*(?:#|--|-|:|$))",
        re.IGNORECASE,
    ),
)
_GENERIC_REASONS = frozenset(
    {
        "because",
        "fix",
        "ignore",
        "needed",
        "silence",
        "temporary",
        "todo",
        "works",
    }
)
_WORD_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")


@dataclass(frozen=True, slots=True)
class _DirectiveMatch:
    """A suppression directive comment that lacks an acceptable reason."""

    comment: SourceComment
    directive: str
    reason: str
    has_reason: bool


class IgnoreDirectiveReasonRule(Rule):
    """Detect suppression comments that do not explain why they are needed."""

    ID = "docs.ignore-directive-reason"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the ignore directive rationale rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Ignore directive reason",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze source comments for unexplained suppression directives.

        Args:
            unit: Source unit whose comments should be scanned.
            context: Rule execution context. Unused; present for the rule API.

        Returns:
            Findings for suppression comments without substantive reasons.
        """
        del context
        definition = self.definition()
        return [
            _directive_finding(unit, definition, match)
            for comment in scan_comments(unit.source)
            if (match := _unexplained_directive(comment)) is not None
        ]


def _unexplained_directive(comment: SourceComment) -> _DirectiveMatch | None:
    body = comment.body
    for pattern in _DIRECTIVE_PATTERNS:
        match = pattern.search(body)
        if match is None:
            continue
        directive = match.group("directive").strip()
        reason = _extract_reason(body, match.end()).strip()
        if _is_substantive_reason(reason):
            return None
        return _DirectiveMatch(
            comment=comment,
            directive=directive,
            reason=reason,
            has_reason=bool(reason),
        )
    return None


def _extract_reason(body: str, directive_end: int) -> str:
    tail = body[directive_end:].strip()
    if not tail:
        return ""
    second_comment = tail.find("#")
    if second_comment >= 0:
        return tail[second_comment + 1 :].strip()
    if tail.startswith("--"):
        return tail[2:].strip()
    if tail.startswith("-"):
        return tail[1:].strip()
    if tail.startswith(":"):
        return tail[1:].strip()
    return tail


def _is_substantive_reason(reason: str) -> bool:
    words = [word.lower() for word in _WORD_PATTERN.findall(reason)]
    if not words:
        return False
    if len(words) == 1 and words[0] in _GENERIC_REASONS:
        return False
    meaningful = [word for word in words if word not in _GENERIC_REASONS]
    return len(meaningful) >= 2


def _directive_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    match: _DirectiveMatch,
) -> Finding:
    reason_message = "without a reason" if not match.has_reason else "with a generic reason"
    return Finding(
        rule_id=definition.id,
        message=f"Suppression directive {match.directive!r} is used {reason_message}.",
        file_path=unit.file.display_path,
        line=match.comment.line,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=match.comment.line,
        remediation=(
            "Add a short rationale that names the compatibility, framework, or "
            "testing reason for the suppression."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "directive": match.directive,
            "reasonPresent": match.has_reason,
            "reason": match.reason,
        },
    )
