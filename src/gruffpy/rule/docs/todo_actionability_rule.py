"""``docs.todo-actionability`` — TODO-style comments need an actionable trail."""

import re
from dataclasses import dataclass
from typing import Any

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

_DEFAULT_MARKERS = ("TODO", "FIXME", "HACK", "XXX", "BUG")
_ISSUE_PATTERN = re.compile(r"(https?://\S+|#\d+\b|[A-Z][A-Z0-9]+-\d+\b)")
_OWNER_PATTERN = re.compile(r"(@[A-Za-z][\w-]*|\b(?:owner|assignee):\s*[A-Za-z][\w-]*)")
_DATE_PATTERN = re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")
_WORD_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_ACTION_VERBS = frozenset(
    {
        "add",
        "audit",
        "delete",
        "document",
        "drop",
        "extract",
        "keep",
        "move",
        "preserve",
        "remove",
        "replace",
        "restore",
        "split",
        "track",
        "update",
    }
)


@dataclass(frozen=True, slots=True)
class _TodoComment:
    """TODO-style comment that lacks an actionable trail."""

    comment: SourceComment
    marker: str
    text: str
    has_issue: bool
    has_owner: bool


class TodoActionabilityRule(Rule):
    """Detect TODO/FIXME/HACK/XXX/BUG comments without actionable context."""

    ID = "docs.todo-actionability"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the TODO actionability rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="TODO actionability",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={
                "markers": list(_DEFAULT_MARKERS),
                "require_issue_or_owner": False,
                "minimum_detail_words": 5,
            },
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze source comments for vague TODO-style markers.

        Args:
            unit: Source unit whose comments should be scanned.
            context: Rule execution context with marker/actionability options.

        Returns:
            Findings for TODO-style comments that cannot be acted on.
        """
        definition = self.definition()
        settings = context.settings_for(definition)
        markers = _markers(settings.options.get("markers"))
        require_issue_or_owner = bool(
            settings.options.get(
                "require_issue_or_owner",
                definition.default_options["require_issue_or_owner"],
            )
        )
        minimum_detail_words = _positive_int(
            settings.options.get(
                "minimum_detail_words",
                definition.default_options["minimum_detail_words"],
            ),
            fallback=int(definition.default_options["minimum_detail_words"]),
        )
        return [
            _todo_finding(unit, definition, todo)
            for comment in scan_comments(unit.source)
            if (
                todo := _unactionable_todo(
                    comment,
                    markers=markers,
                    require_issue_or_owner=require_issue_or_owner,
                    minimum_detail_words=minimum_detail_words,
                )
            )
            is not None
        ]


def _markers(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return _DEFAULT_MARKERS
    cleaned = tuple(marker.strip().upper() for marker in value if marker.strip())
    return cleaned or _DEFAULT_MARKERS


def _positive_int(value: Any, *, fallback: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return fallback


def _unactionable_todo(
    comment: SourceComment,
    *,
    markers: tuple[str, ...],
    require_issue_or_owner: bool,
    minimum_detail_words: int,
) -> _TodoComment | None:
    match = re.search(rf"\b({'|'.join(re.escape(marker) for marker in markers)})\b", comment.body)
    if match is None:
        return None
    marker = match.group(1).upper()
    text = comment.body[match.end() :].strip(" :-")
    has_issue = _ISSUE_PATTERN.search(comment.body) is not None
    has_owner = _OWNER_PATTERN.search(comment.body) is not None
    if require_issue_or_owner:
        actionable = has_issue or has_owner
    else:
        actionable = (
            has_issue
            or has_owner
            or _has_date_plus_action(comment.body, text, minimum_detail_words)
            or _has_detailed_action(text, minimum_detail_words)
        )
    if actionable:
        return None
    return _TodoComment(
        comment=comment,
        marker=marker,
        text=text,
        has_issue=has_issue,
        has_owner=has_owner,
    )


def _has_date_plus_action(body: str, text: str, minimum_detail_words: int) -> bool:
    return _DATE_PATTERN.search(body) is not None and _has_detailed_action(
        text, minimum_detail_words
    )


def _has_detailed_action(text: str, minimum_detail_words: int) -> bool:
    words = [word.lower() for word in _WORD_PATTERN.findall(text)]
    if len(words) < minimum_detail_words:
        return False
    return bool(words and words[0] in _ACTION_VERBS)


def _todo_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    todo: _TodoComment,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=f"{todo.marker} comment is missing an owner, issue, date, or concrete action.",
        file_path=unit.file.display_path,
        line=todo.comment.line,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=todo.comment.line,
        remediation=(
            "Attach an issue, owner, date, or concrete next action so the marker "
            "can be resolved later."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "marker": todo.marker,
            "comment": todo.text,
            "hasIssue": todo.has_issue,
            "hasOwner": todo.has_owner,
        },
    )
