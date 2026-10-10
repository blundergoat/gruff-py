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
- ``gruff.analysis.v2`` gained an additive ``suppressions`` array carrying one
  ``{index, rule, paths, symbol, reason, suppressed}`` audit row per configured
  ``sensitiveExclusions`` entry, including entries that matched nothing. The
  array is always present and is empty when nothing is configured; the shape is
  the family reference gruff-rs already ships. Consumers reading ``findings``
  are unaffected.
- ``gruff.analysis.v3`` is the intentional hard break to one canonical family
  envelope. ``gruff.summary.v3`` is exactly that document with ``findings``
  removed and the schema identifier changed.
- ``gruff.baseline.v3`` replaces ``gruff-py.baseline.v1`` with the family baseline:
  one line-free identity and a count per reviewed occurrence, no positional or
  re-classifiable field, and sensitive findings counted rather than stored. A 0.5
  baseline is refused on read and carried forward by ``--migrate-baseline``.
"""

ANALYSIS_SCHEMA_VERSION = "gruff.analysis.v3"
BASELINE_SCHEMA_VERSION = "gruff.baseline.v3"
LEGACY_BASELINE_SCHEMA_VERSIONS = frozenset({"gruff-py.baseline.v1", "gruff.baseline.v1"})
"""The 0.5 baselines a migration accepts as input; reading one for suppression fails closed and names the migration command."""
HOTSPOT_SCHEMA_VERSION = "gruff-py.hotspot.v1"
SUMMARY_SCHEMA_VERSION = "gruff.summary.v3"
CONFIG_SCHEMA_VERSION = "gruff-py.config.v0.1"
