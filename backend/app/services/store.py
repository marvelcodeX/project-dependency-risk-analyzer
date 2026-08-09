"""Persistence helpers: save a scan and reload it from the database."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Scan, ScanDependency, ScanVulnerability
from app.schemas.scan import (
    Dependency,
    DependencyScanResult,
    ScanResponse,
    Vulnerability,
)


async def save_scan(session: AsyncSession, response: ScanResponse) -> Scan:
    """Persist a completed scan and its results. Returns the saved Scan row."""
    scan = Scan(
        filename=response.filename,
        total_dependencies=response.total_dependencies,
        vulnerable_dependencies=response.vulnerable_dependencies,
        risk_score=response.risk_score,
        risk_level=response.risk_level,
    )

    for result in response.results:
        dep = ScanDependency(
            name=result.dependency.name,
            version=result.dependency.version,
            ecosystem=result.dependency.ecosystem,
            pinned=result.dependency.pinned,
            raw_spec=result.dependency.raw_spec,
        )
        for v in result.vulnerabilities:
            dep.vulnerabilities.append(
                ScanVulnerability(
                    scan=scan,
                    vuln_id=v.id,
                    summary=v.summary,
                    details=v.details,
                    aliases=v.aliases,
                    severity=v.severity,
                    cvss_score=v.cvss_score,
                    cvss_vector=v.cvss_vector,
                    fixed_version=v.fixed_version,
                    references=v.references,
                    in_cisa_kev=v.in_cisa_kev,
                    risk_score=v.risk_score,
                    risk_level=v.risk_level,
                    reachability=v.reachability,
                )
            )
        scan.dependencies.append(dep)

    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def list_scans(session: AsyncSession, limit: int = 50) -> list[Scan]:
    """Return recent scans, newest first (summary rows only)."""
    result = await session.execute(
        select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit)
    )
    return list(result.scalars().all())


async def get_scan(session: AsyncSession, scan_id: int) -> ScanResponse | None:
    """Load a scan and rebuild the full ScanResponse, or None if not found."""
    result = await session.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.dependencies).selectinload(
                ScanDependency.vulnerabilities
            )
        )
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        return None

    results = [
        DependencyScanResult(
            dependency=Dependency(
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                pinned=dep.pinned,
                raw_spec=dep.raw_spec,
            ),
            vulnerabilities=[
                Vulnerability(
                    id=v.vuln_id,
                    summary=v.summary,
                    details=v.details,
                    aliases=v.aliases or [],
                    severity=v.severity,
                    cvss_score=v.cvss_score,
                    cvss_vector=v.cvss_vector,
                    fixed_version=v.fixed_version,
                    references=v.references or [],
                    in_cisa_kev=v.in_cisa_kev,
                    risk_score=v.risk_score,
                    risk_level=v.risk_level,
                    reachability=v.reachability,
                )
                for v in sorted(
                    dep.vulnerabilities, key=lambda x: x.risk_score, reverse=True
                )
            ],
        )
        for dep in scan.dependencies
    ]

    return ScanResponse(
        id=scan.id,
        filename=scan.filename,
        created_at=scan.created_at,
        total_dependencies=scan.total_dependencies,
        vulnerable_dependencies=scan.vulnerable_dependencies,
        risk_score=scan.risk_score,
        risk_level=scan.risk_level,
        results=results,
    )
