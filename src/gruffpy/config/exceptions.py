"""Exception types raised when config loading or validation fails."""


class ConfigError(Exception):
    """Raised when a config file cannot be parsed or contains invalid keys/values."""
