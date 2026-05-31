"""Request model for end-to-end analysis runs.

The CLI and dashboard both validate user input before calling the shared
analysis pipeline. This module keeps that call contract explicit without
making ``run_analysis`` itself own every individual option as a parameter.
"""

from dataclasses import dataclass
from pathlib import Path

from gruffpy.analysis.baseline import BaselineOptions
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.output_format import OutputFormat
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter


@dataclass(frozen=True, slots=True)
class AnalysisRunRequest:
    """Inputs for one end-to-end analysis run.

    Attributes:
        paths: CLI-supplied paths; empty tuple is reported as ``(".",)``.
        config_path: Explicit YAML/TOML config path, or ``None`` to use auto-discovery.
        no_config: When true, skip auto-loading the default config file.
        output: Requested output format recorded on the report.
        fail_threshold: Severity that determines the non-zero exit code.
        include_ignored: When true, scan normally excluded paths.
        project_root: Resolved project root used for display paths and discovery.
        display_filter: Reporter-side filter for severity, pillar, and rule selection.
        baseline: Baseline apply/generate/disable selection.
        config_severity_command: Optional command name for config minimum-severity lookup.
        changed_ranges: Explicit line ranges such as ``3-3,8-10``.
        since: Git base ref for changed-region filtering.
        diff_mode: ``working-tree``, ``staged``, ``unstaged``, a base ref, or ``-``.
        diff_patch: Unified diff text read from stdin for ``--diff -``.
        changed_scope: ``symbol`` or ``hunk`` filtering.
    """

    paths: tuple[str, ...]
    config_path: Path | None
    no_config: bool
    output: OutputFormat
    fail_threshold: FailThreshold
    include_ignored: bool
    project_root: Path
    display_filter: FindingDisplayFilter
    baseline: BaselineOptions | None = None
    config_severity_command: str = ""
    changed_ranges: str = ""
    since: str = ""
    diff_mode: str = ""
    diff_patch: str = ""
    changed_scope: str = "symbol"
