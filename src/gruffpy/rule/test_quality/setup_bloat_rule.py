"""``test-quality.setup-bloat`` - ``setUp`` / ``setup_method`` / fixture is too long.

A setup that's longer than the typical test signals over-shared state. Default
threshold: 30 code lines, measured with the shared ``lines_for_size`` helper.
"""

import ast
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
from gruffpy.rule.security._security_node_helper import call_target_name
from gruffpy.rule.size._lines import code_line_numbers, lines_for_size, parent_chain, qualified_symbol

_SETUP_NAMES: frozenset[str] = frozenset({"setUp", "setUpClass", "setup_method", "setup_class", "setup_function", "setup"})


class SetupBloatRule(Rule):
    """Flag oversized ``setUp``, ``setup_method``, or fixture functions when a project enables ``test-quality.setup-bloat``.

    Measures code lines against ``maxSetupLines`` (default 30) so reviewers can spot over-shared test state.
    Plain ``setup`` functions qualify only on test paths so production lifecycle hooks stay quiet.
    """

    ID = "test-quality.setup-bloat"

    def definition(self) -> RuleDefinition:
        """Describe the setup-bloat rule with a ``maxSetupLines`` threshold (default 30).

        Medium confidence leaves reviewers to judge whether longer setup is warranted for complex object construction.

        Returns:
            Definition with the ``maxSetupLines`` threshold key.
        """
        return RuleDefinition(
            id=self.ID,
            name="Setup bloat",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_enabled=False,
            default_thresholds={"maxSetupLines": 30},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag setup and fixture functions with more than maxSetupLines code lines, counting the function declaration.

        The name setup qualifies as a hook only on a conventional test path. Call-style fixture decorators qualify independently.

        Args:
            unit: Source file to check for oversized setup functions. A missing AST yields no findings. The scan can cache code lines on the AST.
            context: Rule execution context supplying the maxSetupLines threshold.

        Returns:
            One finding per oversized setup/fixture function.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = settings.numeric_threshold("maxSetupLines")
        setup_path = _project_relative_setup_path(unit, context)
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            # Only named setup hooks such as setUp or setup_method, and @pytest.fixture(...) functions, count as setup code.
            if not _is_setup(node, setup_path):
                continue
            lines = lines_for_size(node, code_line_numbers(unit.source, unit.tree))
            if lines <= threshold:
                continue
            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(f"Setup {symbol!r} is {lines} lines, above the threshold of {threshold}."),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=("Shrink the shared setup - extract object factories, narrow what each test actually needs."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"lines": lines, "threshold": threshold},
                ),
            )
        return findings


def _is_setup(fn: ast.FunctionDef | ast.AsyncFunctionDef, source_path: str) -> bool:
    """Recognize setup-hook names and call-style fixture decorators.

    Args:
        fn: Function whose name and decorator calls are checked for setup roles.
        source_path: Source location used to qualify plain setup as a conventional test hook.

    Returns:
        True for a supported setup hook or a decorator call whose final name is fixture; false otherwise.
    """
    if fn.name in _SETUP_NAMES and (fn.name != "setup" or _is_test_setup_path(source_path)):
        return True
    return any((call_target_name(d) or "").split(".")[-1] == "fixture" for d in fn.decorator_list if isinstance(d, ast.Call))


def _project_relative_setup_path(unit: AnalysisUnit, context: RuleContext) -> str:
    """Resolve the unit path relative to the scanned project root for test-path detection.

    Args:
        unit: Source unit supplying the absolute file path.
        context: Rule execution context supplying the scanned project root.

    Returns:
        POSIX path relative to the project root, or the unit's absolute path when the file sits outside that root.
    """
    try:
        return Path(unit.file.absolute_path).relative_to(Path(context.project_root)).as_posix()
    except ValueError:
        # For example, scanning an explicit test file outside the project root keeps its full path so test-directory segments survive.
        return unit.file.absolute_path


def _is_test_setup_path(source_path: str) -> bool:
    """Recognize test paths before treating plain ``setup`` as a test hook.

    Args:
        source_path: Project-relative source path, retaining test directories for explicit-file scans inside the root.

    Returns:
        True for test directories, conftest.py, or conventional test-file names.
    """
    *directories, filename = source_path.replace("\\", "/").lower().split("/")
    return (
        any(directory in {"test", "tests", "testing"} for directory in directories)
        or filename == "conftest.py"
        or (filename.startswith("test_") and filename.endswith(".py"))
        or filename.endswith("_test.py")
    )
