"""Expose the browser dashboard boundaries used by the CLI entry point.

Use these exports when starting a dashboard or rendering its first page from another module.
They connect validated CLI choices to local server state without exposing command internals.
"""

from gruffpy.command.dashboard_page_renderer import DashboardPageRenderer
from gruffpy.command.dashboard_server import DashboardState, create_dashboard_server

__all__ = ["DashboardPageRenderer", "DashboardState", "create_dashboard_server"]
