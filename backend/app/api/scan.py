"""Scan API endpoints."""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_session
from app.parsers.requirements import parse_requirements_txt
from app.schemas.scan import (
    DependencyScanResult,
    ScanListItem,
    ScanRequest,
    ScanResponse,
)
from app.services.kev_client import get_kev_cve_ids
from app.services.osv_client import query_osv
from app.services.risk import compute_risk, risk_level
from app.services import reachability as reach
from app.services import store

router = APIRouter(tags=["scan"])


@router.post("/scan/file", response_model=ScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
):
    """Upload a dependency file and scan for vulnerabilities."""
    content = (await file.read()).decode("utf-8")
    return await _run_scan(content, file.filename or "requirements.txt", session)


@router.post("/scan/text", response_model=ScanResponse)
async def scan_text(
    request: ScanRequest,
    session: AsyncSession = Depends(get_session),
):
    """Submit dependency file content as text and scan for vulnerabilities."""
    return await _run_scan(
        request.content, request.filename, session, request.source_files
    )


@router.get("/scans", response_model=list[ScanListItem])
async def list_scans(session: AsyncSession = Depends(get_session)):
    """List recent scans, newest first."""
    scans = await store.list_scans(session)
    return [
        ScanListItem(
            id=s.id,
            filename=s.filename,
            created_at=s.created_at,
            total_dependencies=s.total_dependencies,
            vulnerable_dependencies=s.vulnerable_dependencies,
            risk_score=s.risk_score,
            risk_level=s.risk_level,
        )
        for s in scans
    ]


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)):
    """Fetch a previously saved scan by id."""
    scan = await store.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


async def _run_scan(
    content: str,
    filename: str,
    session: AsyncSession,
    source_files: dict[str, str] | None = None,
) -> ScanResponse:
    """Core scan pipeline: parse → lookup → enrich → score → persist."""
    # Step 1: Parse dependencies. Only requirements.txt is supported today;
    # other ecosystems (package-lock.json, pom.xml, ...) arrive in Phase 5.
    dependencies = parse_requirements_txt(content)

    # Reachability: analyze provided source once (empty → everything UNKNOWN).
    source_files = source_files or {}
    has_source = bool(source_files)
    imported_modules = reach.analyze_imports(source_files) if has_source else set()

    # KEV catalog is fetched once (cached) and reused for the whole scan.
    kev_ids = await get_kev_cve_ids()

    # Step 2: Query OSV per dependency, then enrich + score each finding.
    results: list[DependencyScanResult] = []
    overall_risk = 0
    for dep in dependencies:
        reachability = reach.classify(dep.name, imported_modules, has_source)
        vulns = await query_osv(dep)
        for v in vulns:
            cve_ids = {a for a in v.aliases if a.startswith("CVE-")}
            if v.id.startswith("CVE-"):
                cve_ids.add(v.id)
            v.in_cisa_kev = bool(cve_ids & kev_ids)
            v.reachability = reachability
            v.risk_score, v.risk_level = compute_risk(
                v, dep, v.in_cisa_kev, reachability
            )
            overall_risk = max(overall_risk, v.risk_score)
        vulns.sort(key=lambda x: x.risk_score, reverse=True)
        results.append(DependencyScanResult(dependency=dep, vulnerabilities=vulns))

    vulnerable_count = sum(1 for r in results if r.vulnerabilities)

    response = ScanResponse(
        filename=filename,
        total_dependencies=len(dependencies),
        vulnerable_dependencies=vulnerable_count,
        risk_score=overall_risk,
        risk_level=risk_level(overall_risk),
        results=results,
    )

    # Step 3: Persist and echo back the saved id + timestamp.
    saved = await store.save_scan(session, response)
    response.id = saved.id
    response.created_at = saved.created_at
    return response
