"""Backing logic for the ``gruff-py check-ignore`` command.

Answers "would gruff ignore this path, and why?" for one or more paths without
running any analysis. It resolves config exactly as ``analyse`` does and reuses
``SourceDiscovery.classify`` so the ignore verdict can never drift from what a
real scan would skip. The JSON shape is the contract coding-agent hooks consume.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.discovery import SourceDiscovery


@dataclass(frozen=True, slots=True)
class CheckIgnoreVerdict:
    """One path's ignore verdict.

    Attributes:
        path: The path exactly as supplied on the command line.
        ignored: Whether gruff would skip this path.
        source: The ignore source when ignored (``config``/``gitignore``/
            ``default``/``generated``), else ``None``.
        pattern: The matched glob/directory/filename when applicable, else ``None``.
    """

    path: str
    ignored: bool
    source: str | None = None
    pattern: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serialisable verdict mapping.

        Returns:
            Mapping with ``path``, ``ignored``, ``source``, and ``pattern`` keys.
        """
        return {
            "path": self.path,
            "ignored": self.ignored,
            "source": self.source,
            "pattern": self.pattern,
        }


def classify_paths(
    *,
    project_root: Path,
    paths: Sequence[str],
    config_path: Path | None,
    no_config: bool,
) -> list[CheckIgnoreVerdict]:
    """Classify each path against the same ignore engine ``analyse`` uses.

    Args:
        project_root: Directory the ignore decision is resolved against.
        paths: Paths to classify, echoed verbatim into the verdicts.
        config_path: Explicit config path, or ``None`` for auto-discovery.
        no_config: When true, skip config loading (no ``paths.ignore``).

    Returns:
        One verdict per input path, in input order.

    Raises:
        ConfigError: When config loading fails (propagated to the CLI for exit 2).
    """
    patterns = _load_ignore_patterns(
        project_root=project_root, config_path=config_path, no_config=no_config
    )
    discovery = SourceDiscovery(project_root)
    verdicts: list[CheckIgnoreVerdict] = []
    for raw_path in paths:
        ignored = discovery.classify(raw_path, configured_ignore_patterns=patterns)
        if ignored is None:
            verdicts.append(CheckIgnoreVerdict(path=raw_path, ignored=False))
        else:
            verdicts.append(
                CheckIgnoreVerdict(
                    path=raw_path,
                    ignored=True,
                    source=ignored.source,
                    pattern=ignored.pattern,
                )
            )
    return verdicts


def _load_ignore_patterns(
    *,
    project_root: Path,
    config_path: Path | None,
    no_config: bool,
) -> tuple[str, ...]:
    if no_config:
        return ()
    base = AnalysisConfig.from_registry(RuleRegistry.defaults())
    loader = ConfigLoader(project_root, base)
    loaded, _source = loader.load(config_path)
    return loaded.ignored_path_patterns


def render_check_ignore_json(verdicts: Sequence[CheckIgnoreVerdict]) -> str:
    """Render verdicts as the agent-facing JSON array contract.

    Args:
        verdicts: Verdicts to serialise (ignored and non-ignored alike).

    Returns:
        Indented JSON array with a trailing newline.
    """
    return json.dumps([verdict.to_dict() for verdict in verdicts], indent=4) + "\n"


def render_check_ignore_text(verdicts: Sequence[CheckIgnoreVerdict]) -> str:
    """Render verdicts as ``git check-ignore``-style text (ignored paths only).

    Each ignored path is printed as ``<path>\\t<source>:<pattern>`` (or
    ``<path>\\t<source>`` when no pattern applies). Non-ignored paths are omitted.

    Args:
        verdicts: Verdicts to render.

    Returns:
        Newline-terminated text, empty when nothing is ignored.
    """
    lines: list[str] = []
    for verdict in verdicts:
        if not verdict.ignored:
            continue
        if verdict.pattern is not None:
            lines.append(f"{verdict.path}\t{verdict.source}:{verdict.pattern}")
        else:
            lines.append(f"{verdict.path}\t{verdict.source}")
    return "".join(f"{line}\n" for line in lines)


def check_ignore_exit_code(verdicts: Sequence[CheckIgnoreVerdict]) -> int:
    """Return the ``git check-ignore``-style exit code.

    Args:
        verdicts: Verdicts produced for the run.

    Returns:
        ``0`` when at least one path is ignored, otherwise ``1``. The CLI maps
        usage/config errors to ``2`` before calling this.
    """
    return 0 if any(verdict.ignored for verdict in verdicts) else 1
