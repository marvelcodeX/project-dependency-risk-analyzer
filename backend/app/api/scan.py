"""Scan API endpoints."""

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_session
from app.parsers import ManifestError
from app.reports import ReportFormat, render_report
from app.schemas.scan import ScanListItem, ScanRequest, ScanResponse
from app.services import scanner, store
from app.services.osv_client import OsvError

router = APIRouter(tags=["scan"])


# Upload size guard: manifests are small; anything bigger is a mistake.
_MAX_UPLOAD_BYTES = 5 * 1024 * 1024


async def _read_text(upload: UploadFile) -> str:
    data = await upload.read(_MAX_UPLOAD_BYTES + 1)
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"{upload.filename} is too large")
    try:
        return data.decode("utf-8-sig")  # tolerate a BOM from Windows editors
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400, detail=f"{upload.filename} is not valid UTF-8 text"
        )


@router.post("/scan/file", response_model=ScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    source_files: list[UploadFile] = File(default=[]),
    session: AsyncSession = Depends(get_session),
):
    """Upload a dependency file (plus optional source for reachability)."""
    content = await _read_text(file)
    sources = {s.filename or "source.py": await _read_text(s) for s in source_files}
    return await _run_scan(content, file.filename or "", session, sources)


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


@router.get("/scans/{scan_id}/report")
async def export_report(
    scan_id: int,
    format: ReportFormat = ReportFormat.json,
    download: bool = True,
    session: AsyncSession = Depends(get_session),
):
    """Export a saved scan as JSON, SARIF, CycloneDX SBOM, Markdown or HTML.

    ``download=false`` serves the report inline (e.g. to open the HTML report
    in a tab and print it to PDF).
    """
    scan = await store.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = render_report(scan, format)
    disposition = "attachment" if download else "inline"
    filename = f"soteria-scan-{scan_id}.{report.extension}"
    return Response(
        content=report.body,
        media_type=report.media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            # The HTML report embeds untrusted advisory text: forbid scripts
            # and remote loads outright, even though everything is escaped.
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
        },
    )


async def _run_scan(
    content: str,
    filename: str,
    session: AsyncSession,
    source_files: dict[str, str] | None = None,
) -> ScanResponse:
    """Run the scan pipeline, map its errors to HTTP, and persist the result."""
    try:
        response = await scanner.scan_manifest(content, filename, source_files)
    except ManifestError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OsvError as exc:
        # Never report "no vulnerabilities" because the database was down.
        raise HTTPException(
            status_code=502,
            detail=f"Vulnerability database (OSV) unavailable: {exc}",
        )

    saved = await store.save_scan(session, response)
    response.id = saved.id
    response.created_at = saved.created_at
    return response
