"""Helpers shared by the report renderers."""

from dataclasses import dataclass
from urllib.parse import quote

from app.schemas.scan import Dependency, ScanResponse, Vulnerability

TOOL_NAME = "Soteria-AI"
TOOL_URI = "https://github.com/marvelcodeX/project-dependency-risk-analyzer"

RISK_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


@dataclass(frozen=True)
class Finding:
    """One vulnerability in one dependency — the unit every report lists."""

    dep: Dependency
    vuln: Vulnerability

    @property
    def cve_ids(self) -> list[str]:
        ids = [a for a in self.vuln.aliases if a.startswith("CVE-")]
        if self.vuln.id.startswith("CVE-") and self.vuln.id not in ids:
            ids.insert(0, self.vuln.id)
        return ids

    @property
    def package_label(self) -> str:
        return f"{self.dep.name} {self.dep.version}" if self.dep.version else self.dep.name


def findings(scan: ScanResponse) -> list[Finding]:
    """All findings in the scan, highest composite risk first."""
    out = [Finding(r.dependency, v) for r in scan.results for v in r.vulnerabilities]
    out.sort(key=lambda f: (-f.vuln.risk_score, f.dep.name, f.vuln.id))
    return out


def osv_url(vuln_id: str) -> str:
    return f"https://osv.dev/vulnerability/{quote(vuln_id, safe='')}"


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def normalized_severity(vuln: Vulnerability) -> str:
    """CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN (``MODERATE`` → ``MEDIUM``)."""
    sev = (vuln.severity or "UNKNOWN").upper()
    if sev == "MODERATE":
        return "MEDIUM"
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        return sev
    if vuln.cvss_score is not None:
        return severity_from_cvss(vuln.cvss_score)
    return "UNKNOWN"


# purl types per OSV ecosystem (https://github.com/package-url/purl-spec).
_PURL_TYPES = {"pypi": "pypi", "npm": "npm", "go": "golang", "maven": "maven"}


def _enc(segment: str) -> str:
    return quote(segment, safe=".-_~")


def purl(dep: Dependency) -> str | None:
    """Package URL for a dependency, or ``None`` for unknown ecosystems."""
    eco = dep.ecosystem.lower()
    ptype = _PURL_TYPES.get(eco)
    if ptype is None:
        return None

    if eco == "pypi":
        # purl-spec: PyPI names are lowercased with "_" replaced by "-".
        path = _enc(dep.name.lower().replace("_", "-"))
    elif eco == "npm":
        if dep.name.startswith("@") and "/" in dep.name:
            scope, name = dep.name.split("/", 1)
            path = f"{_enc(scope)}/{_enc(name)}"  # "@" becomes %40
        else:
            path = _enc(dep.name)
    elif eco == "maven":
        group, _, artifact = dep.name.partition(":")
        path = f"{_enc(group)}/{_enc(artifact)}" if artifact else _enc(group)
    else:  # golang: module path segments are the namespace + name
        path = "/".join(_enc(p) for p in dep.name.split("/"))

    version = dep.version
    if version and eco == "go" and not version.startswith("v"):
        version = "v" + version  # Go module versions carry the "v"
    return f"pkg:{ptype}/{path}" + (f"@{_enc(version)}" if version else "")


def component_ref(dep: Dependency) -> str:
    """Stable, unique reference for a dependency within one report."""
    return purl(dep) or f"{dep.ecosystem}:{dep.name}@{dep.version or ''}"
