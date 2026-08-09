"""Pydantic schemas for scan requests and responses."""

from datetime import datetime

from pydantic import BaseModel


class Dependency(BaseModel):
    name: str
    version: str | None = None
    ecosystem: str = "PyPI"
    pinned: bool = False
    raw_spec: str = ""


class Vulnerability(BaseModel):
    id: str
    summary: str
    details: str = ""
    aliases: list[str] = []
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    fixed_version: str | None = None
    references: list[str] = []
    # Phase 2 enrichment (populated by the scan pipeline).
    in_cisa_kev: bool = False
    risk_score: int = 0
    risk_level: str = "NONE"
    # Phase 3 reachability: UNKNOWN / REACHABLE / POTENTIALLY_REACHABLE / UNREACHABLE
    reachability: str = "UNKNOWN"


class DependencyScanResult(BaseModel):
    dependency: Dependency
    vulnerabilities: list[Vulnerability] = []


class ScanRequest(BaseModel):
    content: str
    filename: str = "requirements.txt"
    # Optional project source for reachability analysis: {filename: code}.
    source_files: dict[str, str] = {}


class ScanResponse(BaseModel):
    id: int | None = None
    filename: str = "requirements.txt"
    created_at: datetime | None = None
    total_dependencies: int
    vulnerable_dependencies: int
    # Overall project risk = highest per-vuln risk score in the scan.
    risk_score: int = 0
    risk_level: str = "NONE"
    results: list[DependencyScanResult]


class ScanListItem(BaseModel):
    """Lightweight summary for the scan-history list endpoint."""

    id: int
    filename: str
    created_at: datetime
    total_dependencies: int
    vulnerable_dependencies: int
    risk_score: int
    risk_level: str
