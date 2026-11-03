"""Indexed catalogue of every built-in rule, keyed by rule id."""

import json
from collections.abc import Iterable

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.finding.finding import Finding
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.rule import Rule, SourceTextRule

RuleLike = Rule | ProjectRuleProtocol


class RuleRegistry:
    """Sorted in-memory registry for rule lookup and execution."""

    def __init__(self, rule_like_items: Iterable[RuleLike]) -> None:
        indexed: dict[str, RuleLike] = {}
        for rule in rule_like_items:
            rule_id = rule.definition().id
            if rule_id in indexed:
                raise ValueError(f'Duplicate rule id "{rule_id}".')
            indexed[rule_id] = rule
        self._rules: dict[str, RuleLike] = dict(sorted(indexed.items()))

    @classmethod
    def defaults(cls) -> "RuleRegistry":
        """Build a registry containing every built-in rule.

        Returns:
            Registry populated from the rule catalog.
        """
        from gruffpy.rule.catalog import default_rules

        return cls(default_rules())

    def all(self) -> list[RuleLike]:
        """Return every registered rule in deterministic id order.

        Returns:
            Registered rule instances sorted by rule id.
        """
        return list(self._rules.values())

    def has(self, rule_id: str) -> bool:
        """Return whether a rule id is registered.

        Args:
            rule_id: Rule identifier to check.

        Returns:
            True when the registry contains the rule id.
        """
        return rule_id in self._rules

    def get(self, rule_id: str) -> RuleLike:
        """Return a registered rule by id.

        Args:
            rule_id: Rule identifier to resolve.

        Returns:
            Registered rule instance for the id.

        Raises:
            KeyError: If the rule id is unknown.
        """
        if rule_id not in self._rules:
            raise KeyError(f'Unknown rule id "{rule_id}".')
        return self._rules[rule_id]

    def enabled_rules(self, config: AnalysisConfig) -> list[RuleLike]:
        """Return rules enabled by the current analysis configuration.

        Args:
            config: Analysis configuration with rule settings and selection.

        Returns:
            Registered rules allowed by both per-rule settings and profile filters.
        """
        result: list[RuleLike] = []
        for rule in self._rules.values():
            definition = rule.definition()
            settings = config.rule_settings(definition.id)
            if settings.enabled and config.rule_selection.is_allowed(definition):
                result.append(rule)
        return result

    def analyse(self, units: list[AnalysisUnit], context: RuleContext) -> list[Finding]:
        """Run enabled source and project rules over analysis units.

        Args:
            units: Parsed and source-text analysis units to inspect.
            context: Rule execution context containing configuration and paths.

        Returns:
            Deduplicated findings sorted into deterministic output order.
        """
        enabled = self.enabled_rules(context.config)
        python_rules, text_rules, project_rules = self._partition_rules(enabled)
        findings = self._analyse_units(units, context, python_rules, text_rules)
        project_units = self._project_units(units)
        findings.extend(self._analyse_project_rules(project_units, context, project_rules))
        findings = self._deduplicate(findings)
        findings.sort(key=lambda f: (f.file_path, f.line if f.line is not None else 0, f.rule_id, f.message))
        return findings

    @staticmethod
    def _partition_rules(
        rules: list[RuleLike],
    ) -> tuple[list[Rule], list[SourceTextRule], list[ProjectRuleProtocol]]:
        """Split the enabled rules into Python rules, source-text rules and project rules so each rule runs through one analysis path.

        Args:
            rules: Enabled rules in registry id order, as returned by enabled_rules.

        Returns:
            A tuple of Python rules, source-text rules and project rules, each keeping the input order; a rule that is neither a project rule nor a
            SourceTextRule is placed in the Python rule list.
        """
        # Project-rule check must come first: a rule satisfying ProjectRuleProtocol
        # is dispatched only through analyse_project, mirroring the prior inline
        # `if isinstance(rule, ProjectRuleProtocol): continue` guard.
        python_rules: list[Rule] = []
        text_rules: list[SourceTextRule] = []
        project_rules: list[ProjectRuleProtocol] = []
        for rule in rules:
            if isinstance(rule, ProjectRuleProtocol):
                project_rules.append(rule)
            elif isinstance(rule, SourceTextRule):
                text_rules.append(rule)
            else:
                python_rules.append(rule)
        return python_rules, text_rules, project_rules

    @staticmethod
    def _project_units(units: list[AnalysisUnit]) -> list[AnalysisUnit]:
        """Select the Python units that parsed cleanly and carry a syntax tree, for project rules to inspect.

        Args:
            units: Every analysis unit discovered for the run, including non-Python files and units with parse errors.

        Returns:
            Units whose file is Python, which have no parse errors and whose tree is not None, in input order; empty when no unit qualifies.
        """
        return [unit for unit in units if not unit.has_parse_errors() and unit.file.is_python() and unit.tree is not None]

    @staticmethod
    def _analyse_units(
        units: list[AnalysisUnit],
        context: RuleContext,
        python_rules: list[Rule],
        text_rules: list[SourceTextRule],
    ) -> list[Finding]:
        """Run the per-file Python rules and source-text rules over every unit and collect their findings.

        Args:
            units: Every analysis unit discovered for the run; each is passed to _analyse_unit, which decides which rules apply to it.
            context: Rule context passed unchanged to every rule's analyse call.
            python_rules: Enabled per-file Python rules; _analyse_unit decides which of them run on each unit.
            text_rules: Enabled source-text rules, run on every unit, including non-Python files and units with parse errors.

        Returns:
            Findings grouped by unit in input order, with each unit's Python rule findings before its source-text rule findings; not yet deduplicated
            or sorted.
        """
        findings: list[Finding] = []
        for unit in units:
            findings.extend(RuleRegistry._analyse_unit(unit, context, python_rules, text_rules))
        return findings

    @staticmethod
    def _analyse_unit(
        unit: AnalysisUnit,
        context: RuleContext,
        python_rules: list[Rule],
        text_rules: list[SourceTextRule],
    ) -> list[Finding]:
        """Run only the rule families supported by this unit's parse state.

        Args:
            unit: Analysis unit being checked; its file type, parse errors and deep-scan bound decide which Python rules run.
            context: Rule context passed unchanged to every rule's analyse call.
            python_rules: Enabled Python rules; all run on a Python unit that parsed cleanly and is not deep-scan bounded, only size.file-length runs
                on a deep-scan-bounded Python unit, and none run on any other unit.
            text_rules: Enabled source-text rules, run on every unit, including non-Python files and units with parse errors.

        Returns:
            Findings from the applicable Python rules followed by those from the source-text rules, each in rule order; empty when no rule reports
            anything.
        """
        findings: list[Finding] = []
        # A broken Python file retains useful source text but has no AST that
        # Python rules can inspect honestly.
        if unit.file.is_python() and not unit.has_parse_errors() and not unit.is_deep_scan_bounded():
            # Parseable Python units follow the existing per-file AST rule order.
            for rule in python_rules:
                findings.extend(rule.analyse(unit, context))
        elif unit.file.is_python() and unit.is_deep_scan_bounded():
            for rule in python_rules:
                if rule.definition().id == "size.file-length":
                    findings.extend(rule.analyse(unit, context))
        # Every discovered unit keeps its original source, including parser failures.
        for rule in text_rules:
            findings.extend(rule.analyse(unit, context))
        return findings

    @staticmethod
    def _analyse_project_rules(
        units: list[AnalysisUnit],
        context: RuleContext,
        rules: list[ProjectRuleProtocol],
    ) -> list[Finding]:
        """Run each project rule once over the given unit list and collect the findings.

        Args:
            units: Units the project rules may inspect; analyse passes only the cleanly parsed Python units selected by _project_units.
            context: Rule context passed unchanged to every project rule's analyse_project call.
            rules: Enabled project rules.

        Returns:
            Findings from every project rule in rule order; empty when there are no project rules or none reports anything.
        """
        findings: list[Finding] = []
        for rule in rules:
            findings.extend(rule.analyse_project(units, context))
        return findings

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Drop repeated findings, keeping the first occurrence of each.

        Two findings are duplicates when their rule id, file path, line, end line, column, symbol, message and metadata all match; metadata is
        compared as JSON with sorted keys, and an absent line, end line, column or symbol compares as an empty value. Fields outside this key are not
        compared.

        Args:
            findings: Findings collected from the per-file and project rule passes, in collection order.

        Returns:
            A new list holding the first finding for each distinct key, in the original order.
        """
        seen: set[tuple[str, ...]] = set()
        result: list[Finding] = []
        for finding in findings:
            key = (
                finding.rule_id,
                finding.file_path,
                str(finding.line) if finding.line is not None else "",
                str(finding.end_line) if finding.end_line is not None else "",
                str(finding.column) if finding.column is not None else "",
                finding.symbol or "",
                finding.message,
                json.dumps(finding.metadata, sort_keys=True),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(finding)
        return result
