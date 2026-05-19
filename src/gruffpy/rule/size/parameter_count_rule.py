"""``size.parameter-count`` — too many parameters make calls error-prone."""

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
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class ParameterCountRule(Rule):
    """Flag functions whose total arity (excluding ``self``/``cls``) exceeds the threshold."""

    ID = "size.parameter-count"

    def definition(self) -> RuleDefinition:
        """Describe the parameter-count rule with a configurable arity threshold (default 10).

        Returns:
            Definition under the size pillar; parameter count includes
            ``*args``/``**kwargs`` but excludes ``self``/``cls``.
        """
        return RuleDefinition(
            id=self.ID,
            name="Parameter count",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 10, "error": 10},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per function whose total parameter arity exceeds the threshold.

        Counts positional-only + positional + keyword-only + ``*args`` +
        ``**kwargs``. Method receivers (``self``/``cls``) are excluded so a
        9-parameter free function and a 9-parameter method compare on equal
        footing.

        Args:
            unit: Parsed source file to walk.
            context: Rule execution context that supplies the threshold.

        Returns:
            One finding per function whose adjusted arity is over threshold.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            count = _count_parameters(node, parents)
            threshold_match = settings.high_value_threshold_match(count)
            if threshold_match is None:
                continue

            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has {count} parameters, "
                        f"above the {threshold_match.severity.value} threshold of "
                        f"{_format_number(threshold_match.threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=threshold_match.severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Group related parameters into a dataclass or context object, "
                        "or split the function."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "parameters": count,
                        "measuredValue": count,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                    },
                ),
            )

        return findings


def _count_parameters(fn: ast.FunctionDef | ast.AsyncFunctionDef, parents: list[ast.AST]) -> int:
    args = fn.args
    positional = list(args.posonlyargs) + list(args.args)
    if positional and _is_method(fn, parents):
        first_name = positional[0].arg
        if first_name in {"self", "cls"}:
            positional = positional[1:]
    count = len(positional) + len(args.kwonlyargs)
    if args.vararg is not None:
        count += 1
    if args.kwarg is not None:
        count += 1
    return count


def _is_method(_fn: ast.FunctionDef | ast.AsyncFunctionDef, parents: list[ast.AST]) -> bool:
    return any(isinstance(p, ast.ClassDef) for p in parents)


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
