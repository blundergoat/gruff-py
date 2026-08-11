"""Start the gruff-py CLI for users running the package as a module.

Use this entry point for ``python -m gruffpy`` instead of the installed executable.
It hands the request to the same Click command tree, output, and exit handling.
"""

from typing import cast

import click

from gruffpy.cli import main

cast(click.Group, main)()
