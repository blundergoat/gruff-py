import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.design.single_implementor_protocol_rule import SingleImplementorProtocolRule
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(
            absolute_path=f"/workspace/{display_path}",
            display_path=display_path,
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _analyse(*units: AnalysisUnit):
    registry = RuleRegistry([SingleImplementorProtocolRule()])
    config = AnalysisConfig.from_registry(registry)
    context = RuleContext(project_root="/workspace", config=config)
    return registry.analyse(list(units), context)


def test_single_implementor_protocol_without_external_usage_is_flagged():
    contract = _unit(
        "from typing import Protocol\n\n"
        "class Renderer(Protocol):\n"
        "    def render(self, value: str) -> str: ...\n",
        "src/contracts.py",
    )
    implementation = _unit(
        "from .contracts import Renderer\n\n"
        "class HtmlRenderer(Renderer):\n"
        "    def render(self, value: str) -> str:\n"
        "        return value\n",
        "src/html_renderer.py",
    )

    findings = _analyse(contract, implementation)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "design.single-implementor-protocol"
    assert finding.file_path == "src/contracts.py"
    assert finding.symbol == "src.contracts.Renderer"
    assert finding.metadata["implementorFqn"] == "src.html_renderer.HtmlRenderer"


def test_multiple_implementors_skip_protocol():
    contract = _unit(
        "from typing import Protocol\n\nclass Renderer(Protocol):\n    pass\n",
        "src/contracts.py",
    )
    implementations = _unit(
        "from .contracts import Renderer\n\n"
        "class HtmlRenderer(Renderer):\n"
        "    pass\n\n"
        "class TextRenderer(Renderer):\n"
        "    pass\n",
        "src/renderers.py",
    )

    assert _analyse(contract, implementations) == []


def test_external_type_hint_usage_skips_protocol():
    source = _unit(
        "from typing import Protocol\n\n"
        "class Renderer(Protocol):\n"
        "    pass\n\n"
        "class HtmlRenderer(Renderer):\n"
        "    pass\n\n"
        "def render_with(renderer: Renderer) -> None:\n"
        "    return None\n",
        "src/rendering.py",
    )

    assert _analyse(source) == []
