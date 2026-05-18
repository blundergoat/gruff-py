"""Module execution entry point that delegates ``python -m gruffpy`` to the Click CLI."""

from typing import cast

import click

from gruffpy.cli import main

cast(click.Group, main)()
