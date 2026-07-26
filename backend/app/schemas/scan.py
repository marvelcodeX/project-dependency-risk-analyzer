"""Pydantic schemas for scan requests and responses."""

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
    fixed_version: str | None = None
    references: list[str] = []


class DependencyScanResult(BaseModel):
    dependency: Dependency
    vulnerabilities: list[Vulnerability] = []


class ScanRequest(BaseModel):
    content: str
    filename: str = "requirements.txt"


class ScanResponse(BaseModel):
    total_dependencies: int
    vulnerable_dependencies: int
    results: list[DependencyScanResult]
