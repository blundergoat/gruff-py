"""Schema version strings emitted by gruff-py reports and accepted by its config loader.

Schema history (additive changes keep the version string; only a breaking change
bumps it, per the cross-impl CONTRACT.md compatibility policy):

- ``gruff-py.analysis.v1`` gained an additive ``ignoredPathDetails`` array
  (objects with ``path``/``source``/``pattern``) alongside the existing
  string ``ignoredPaths``. ``source`` is one of ``config``/``gitignore``/
  ``default``/``generated``; ``pattern`` is the matched glob for ``config``,
  the matched directory for ``default``, the lockfile name for ``generated``,
  and ``null`` for ``gitignore``. Existing consumers reading ``ignoredPaths``
  as a list of strings are unaffected.
- ``gruff.analysis.v2`` replaces the language-prefixed analysis schema string
  for cross-port JSON consumers. Baseline, hotspot, summary, and config schema
  strings are unchanged.
"""

ANALYSIS_SCHEMA_VERSION = "gruff.analysis.v2"
BASELINE_SCHEMA_VERSION = "gruff-py.baseline.v1"
HOTSPOT_SCHEMA_VERSION = "gruff-py.hotspot.v1"
SUMMARY_SCHEMA_VERSION = "gruff.summary.v2"
CONFIG_SCHEMA_VERSION = "gruff-py.config.v0.1"
