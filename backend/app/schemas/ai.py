"""Schemas for the AI explanation layer."""

from pydantic import BaseModel, field_validator

# Priorities the model is asked to choose from (plan section 9.3).
PRIORITIES = {"FIX_NOW", "FIX_THIS_WEEK", "FIX_WHEN_CONVENIENT", "MONITOR"}


class ExplainRequest(BaseModel):
    """Everything the prompt needs about one finding, sent by the frontend."""

    vuln_id: str
    cve_id: str | None = None
    package: str
    version: str | None = None
    ecosystem: str = "PyPI"
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    summary: str = ""
    details: str = ""
    fixed_version: str | None = None
    in_cisa_kev: bool = False
    risk_level: str = "NONE"
    reachability: str = "UNKNOWN"


class AiExplanation(BaseModel):
    """Structured, plain-English explanation of a vulnerability."""

    summary: str
    attack_scenario: str
    project_impact: str
    fix_steps: str
    priority: str = "MONITOR"

    @field_validator("priority")
    @classmethod
    def _normalize_priority(cls, v: str) -> str:
        cleaned = (v or "").strip().upper().replace(" ", "_").replace("-", "_")
        return cleaned if cleaned in PRIORITIES else "MONITOR"


class AiExplanationOut(AiExplanation):
    """Explanation plus provenance for the client."""

    model: str
    cached: bool


class AiStatus(BaseModel):
    available: bool
    model: str
    detail: str = ""
