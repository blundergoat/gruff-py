"""The two bands every size and complexity finding reports in.

FAMILY-CONTRACT.md section 12, "Size and complexity findings in two bands": a unit over its limit but under one and a
half times it gets an advisory notice not to grow, and one at that ratio or above keeps its severity and the advice to
split or simplify. The message never changes between bands, so a finding keeps its identity when its unit crosses the
boundary; the band shows in the severity, the advice and the ``limitBand`` metadata key.
"""

from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity

LIMIT_BAND_KEY = "limitBand"
LOWER = "lower"
UPPER = "upper"
_RATIO = 1.5

LOWER_FUNCTION = "Do not add to this function; put new code in a new function."
LOWER_FILE = "Do not add to this file; put new code in a new file."
LOWER_CLASS = "Do not add to this class; put new code in a new class."
LOWER_PARAMETER = "Do not add another parameter to this function."
LOWER_ATTRIBUTE = "Do not add another attribute to this class."
LOWER_PUBLIC_METHOD = "Do not add another public method to this class."
SPLIT_FILE = "Split this file by responsibility, one responsibility per file."
SPLIT_CLASS = "Split this class by responsibility: move each group of members that work together into its own class."
SPLIT_FUNCTION = "Split this function at its steps, one step per function."
GROUP_PARAMETERS = "Group the parameters that travel together into one object, or split the function by caller."
SIMPLIFY_PATH = (
    "Simplify the execution path: return early, merge branches that lead to the same result, and drop flags that steer "
    "later branches. Moving branches into helpers leaves the path as hard to follow."
)


def limit_in_force(settings: RuleSettings) -> int | float:
    """Return the limit a "higher is worse" measurement is banded against.

    Args:
        settings: The rule's effective settings.

    Returns:
        The single-threshold override when one is set, otherwise the warning tier: the lowest limit at which the
        rule reports.
    """
    if settings.severity_threshold is not None:
        return settings.severity_threshold.threshold
    return settings.numeric_threshold("warning")


def limit_band(measured: int | float, limit: int | float) -> str:
    """Name the band a measured value falls in, compared without rounding.

    Args:
        measured: The size or complexity the rule measured.
        limit: The limit in force for the unit.

    Returns:
        ``UPPER`` at or above one and a half times the limit, otherwise ``LOWER``.
    """
    return UPPER if measured >= _RATIO * limit else LOWER


def banded_severity(band: str, severity: Severity) -> Severity:
    """Give a finding its band's severity.

    Args:
        band: The finding's band, from ``limit_band``.
        severity: The severity the finding has without bands.

    Returns:
        ``Severity.ADVISORY`` in the lower band, whatever the rule's severity; otherwise the severity given.
    """
    return Severity.ADVISORY if band == LOWER else severity


def band_advice(band: str, lower: str, upper: str) -> str:
    """Pick the advice for a finding's band.

    Args:
        band: The finding's band, from ``limit_band``.
        lower: The do-not-grow advice for this kind of unit.
        upper: The advice to split or simplify the unit.

    Returns:
        The lower-band advice in the lower band, otherwise the upper-band advice.
    """
    return lower if band == LOWER else upper
