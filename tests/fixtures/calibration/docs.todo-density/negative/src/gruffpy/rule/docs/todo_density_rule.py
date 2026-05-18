"""Fixture mirroring a rule file that documents TODO-style markers."""

# TODO: appears here as an example marker.
# FIXME: appears here as an example marker.
# HACK: appears here as an example marker.
# XXX: appears here as an example marker.
# BUG: appears here as an example marker.


def marker_examples() -> tuple[str, ...]:
    return ("TODO", "FIXME", "HACK", "XXX", "BUG")
