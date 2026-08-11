"""Expose gruff-py's public package identity to Python callers.

Use this module when an integration needs to identify the installed analyser.
It keeps the imported version aligned with the name shown by the CLI.
"""

from gruffpy.version import VERSION

__version__ = VERSION
