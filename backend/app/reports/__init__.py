"""Exportable scan reports: JSON, SARIF, CycloneDX SBOM, Markdown, HTML."""

import json
from dataclasses import dataclass
from enum import Enum

from app.reports.cyclonedx import render_cyclonedx
from app.reports.html_report import render_html
from app.reports.markdown import render_markdown
from app.reports.sarif import render_sarif
from app.schemas.scan import ScanResponse


class ReportFormat(str, Enum):
    json = "json"
    sarif = "sarif"
    cyclonedx = "cyclonedx"
    markdown = "markdown"
    html = "html"


@dataclass(frozen=True)
class RenderedReport:
    body: str
    media_type: str
    extension: str


def render_report(scan: ScanResponse, fmt: ReportFormat) -> RenderedReport:
    """Render a saved scan in the requested format."""
    if fmt is ReportFormat.json:
        return RenderedReport(scan.model_dump_json(indent=2), "application/json", "json")
    if fmt is ReportFormat.sarif:
        body = json.dumps(render_sarif(scan), indent=2)
        return RenderedReport(body, "application/sarif+json", "sarif")
    if fmt is ReportFormat.cyclonedx:
        body = json.dumps(render_cyclonedx(scan), indent=2)
        return RenderedReport(body, "application/vnd.cyclonedx+json", "cdx.json")
    if fmt is ReportFormat.markdown:
        return RenderedReport(render_markdown(scan), "text/markdown; charset=utf-8", "md")
    return RenderedReport(render_html(scan), "text/html; charset=utf-8", "html")
