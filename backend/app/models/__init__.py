"""ORM models. Importing this package registers all tables on Base.metadata."""

from app.models.ai import AiExplanationCache
from app.models.scan import Scan, ScanDependency, ScanVulnerability

__all__ = [
    "Scan",
    "ScanDependency",
    "ScanVulnerability",
    "AiExplanationCache",
]
