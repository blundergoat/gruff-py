"""Entry point for ``python -m gruffpy``."""

from typing import cast

import click

from gruffpy.cli import main

cast(click.Group, main)()
