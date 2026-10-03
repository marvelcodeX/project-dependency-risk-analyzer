"""Errors shared by the manifest parsers."""


class ManifestError(ValueError):
    """Raised when a dependency manifest can't be parsed at all."""
