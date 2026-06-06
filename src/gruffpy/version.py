"""gruff-py's public tool identity (name and version).

``VERSION`` is kept in lockstep with ``pyproject.toml``'s ``project.version`` by
``scripts/bump-version.sh`` (run it with ``--check`` to detect drift); change the
version through that script rather than editing either file by hand.
"""

TOOL_NAME = "gruff-py"
VERSION = "0.3.1"
