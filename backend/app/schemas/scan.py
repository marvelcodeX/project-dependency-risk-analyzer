"""Pydantic schemas for scan requests and responses."""

from datetime import datetime

from pydantic import BaseModel


class Dependency(BaseModel):
    name: str
    version: str | None = None
    ecosystem: str = "PyPI"
    pinned: bool = False
    raw_spec: str = ""
    # Dependency graph. None = unknown (the manifest doesn't say).
    direct: bool | None = None
    depth: int | None = None  # 0 = direct, 1+ = transitive hops
    depends_on: list[str] = []  # keys ("name@version") of this package's deps
    # "declared" = from the manifest; "latest" = resolved from the registry
    # because the manifest gave no usable version (e.g. a bare "numpy").
    version_source: str = "declared"

    @property
    def key(self) -> str:
        """Graph key used in ``depends_on``."""
        return f"{self.name}@{self.version or ''}"


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
    # Enrichment: CWE weakness ids and whether a public exploit/PoC exists.
    cwe_ids: list[str] = []
    has_public_exploit: bool = False


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
    total_findings: int = 0


class ManifestFormat(BaseModel):
    """One supported manifest format (GET /api/ecosystems)."""

    format: str
    ecosystem: str
    reachability: bool  # whether source can be analyzed for this ecosystem
