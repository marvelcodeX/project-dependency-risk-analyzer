"""Scan API endpoints."""

from fastapi import APIRouter, UploadFile, File
from app.parsers.requirements import parse_requirements_txt
from app.services.osv_client import query_osv
from app.schemas.scan import ScanResponse, DependencyScanResult, ScanRequest

router = APIRouter(tags=["scan"])


@router.post("/scan/file", response_model=ScanResponse)
async def scan_file(file: UploadFile = File(...)):
    """Upload a dependency file and scan for vulnerabilities."""
    content = (await file.read()).decode("utf-8")
    return await _run_scan(content, file.filename or "requirements.txt")


@router.post("/scan/text", response_model=ScanResponse)
async def scan_text(request: ScanRequest):
    """Submit dependency file content as text and scan for vulnerabilities."""
    return await _run_scan(request.content, request.filename)


async def _run_scan(content: str, filename: str) -> ScanResponse:
    """Core scan pipeline: parse → lookup → respond."""
    # Step 1: Parse dependencies
    if filename.endswith(".txt") or filename == "requirements.txt":
        dependencies = parse_requirements_txt(content)
    else:
        dependencies = parse_requirements_txt(content)  # fallback for now

    # Step 2: Query OSV for each dependency
    results: list[DependencyScanResult] = []
    for dep in dependencies:
        vulns = await query_osv(dep)
        results.append(DependencyScanResult(dependency=dep, vulnerabilities=vulns))

    vulnerable_count = sum(1 for r in results if r.vulnerabilities)

    return ScanResponse(
        total_dependencies=len(dependencies),
        vulnerable_dependencies=vulnerable_count,
        results=results,
    )
