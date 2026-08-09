"""Client for a local Ollama LLM server.

Generates plain-English vulnerability explanations. All data stays local — no
cloud APIs. Ollama is optional: if the server isn't running, `is_available`
returns False and `generate` raises `OllamaError` so callers can degrade
gracefully.
"""

import json

import httpx

from app.core.config import settings
from app.schemas.ai import AiExplanation, ExplainRequest

SYSTEM_PROMPT = (
    "You are a senior security analyst explaining a software dependency "
    "vulnerability to a developer who is NOT a security expert. Be clear, "
    "specific, and actionable. Avoid jargon; when you must use a term, explain "
    "it. Base your answer only on the data provided — do not invent CVE details."
)


class OllamaError(RuntimeError):
    """Raised when the Ollama server is unreachable or returns an error."""


# Plain-English reachability context for the prompt.
_REACHABILITY_TEXT = {
    "REACHABLE": "REACHABLE — the project's code imports this package",
    "UNREACHABLE": "UNREACHABLE — the package is not imported anywhere in the "
    "analyzed source (lower real-world risk for this project)",
    "POTENTIALLY_REACHABLE": "POTENTIALLY REACHABLE — source was analyzed but "
    "we could not confirm the import",
    "UNKNOWN": "UNKNOWN — no project source was provided for analysis",
}


def _build_prompt(req: ExplainRequest) -> str:
    """Render the finding into a structured prompt requesting JSON output."""
    version = req.version or "unspecified"
    fix = req.fixed_version or "no fixed version published"
    kev = "YES — actively exploited in the wild" if req.in_cisa_kev else "no"
    cvss = f"{req.cvss_score}" if req.cvss_score is not None else "not available"
    reach = _REACHABILITY_TEXT.get(req.reachability, req.reachability)
    return f"""VULNERABILITY DATA
- Advisory ID: {req.vuln_id}
- CVE: {req.cve_id or "n/a"}
- Package: {req.package} {version} ({req.ecosystem})
- Severity: {req.severity} (CVSS {cvss})
- In CISA KEV (exploited in the wild): {kev}
- Reachability in this project: {reach}
- Composite risk level: {req.risk_level}
- Fixed version: {fix}
- Summary: {req.summary or "n/a"}
- Details: {(req.details or "n/a")[:1500]}

Respond with a JSON object using EXACTLY these keys, each a plain-English string:
- "summary": 2-3 sentences on what the vulnerability is.
- "attack_scenario": a concrete "An attacker could..." scenario.
- "project_impact": what it realistically means for a project using this package.
- "fix_steps": step-by-step remediation, including the upgrade command; note if a
  fixed version exists. Mention breaking-change risk in general terms.
- "priority": one of "FIX_NOW", "FIX_THIS_WEEK", "FIX_WHEN_CONVENIENT", "MONITOR".
Return only the JSON object, no prose before or after."""


async def is_available() -> bool:
    """True if the Ollama server responds. Best-effort, short timeout."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.ollama_url}/api/tags")
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


async def generate(req: ExplainRequest) -> AiExplanation:
    """Generate a structured explanation. Raises OllamaError on failure."""
    payload = {
        "model": settings.ollama_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_prompt(req)},
        ],
        "stream": False,
        "format": "json",  # constrain output to valid JSON
        "options": {"temperature": 0.2},
    }
    try:
        async with httpx.AsyncClient(timeout=settings.ollama_timeout) as client:
            resp = await client.post(
                f"{settings.ollama_url}/api/chat", json=payload
            )
        resp.raise_for_status()
        content = resp.json()["message"]["content"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        raise OllamaError(str(exc)) from exc

    return _parse(content)


def _as_text(value) -> str:
    """Coerce a JSON value to readable text. Models sometimes return a list of
    steps or a nested object where a string was requested."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        # Render a list as newline-separated steps.
        return "\n".join(_as_text(item) for item in value if item is not None)
    if isinstance(value, dict):
        return "\n".join(f"{k}: {_as_text(v)}" for k, v in value.items())
    return str(value)


def _parse(content: str) -> AiExplanation:
    """Parse the model's JSON reply into an AiExplanation, tolerating slop."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        # Model didn't return valid JSON despite format=json — degrade to
        # putting the raw text in the summary rather than failing outright.
        return AiExplanation(
            summary=content.strip()[:2000] or "No explanation produced.",
            attack_scenario="",
            project_impact="",
            fix_steps="",
            priority="MONITOR",
        )
    if not isinstance(data, dict):
        data = {"summary": _as_text(data)}
    return AiExplanation(
        summary=_as_text(data.get("summary")),
        attack_scenario=_as_text(data.get("attack_scenario")),
        project_impact=_as_text(data.get("project_impact")),
        fix_steps=_as_text(data.get("fix_steps")),
        priority=str(data.get("priority", "MONITOR")),
    )
