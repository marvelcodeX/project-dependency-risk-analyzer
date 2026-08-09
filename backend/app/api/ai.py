"""AI explanation endpoints (local LLM via Ollama)."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_session
from app.schemas.ai import AiExplanationOut, AiStatus, ExplainRequest
from app.services import ai as ai_service
from app.services import ollama_client

router = APIRouter(tags=["ai"], prefix="/ai")


@router.get("/status", response_model=AiStatus)
async def ai_status():
    """Report whether the local LLM is reachable, so the UI can adapt."""
    available = await ollama_client.is_available()
    return AiStatus(
        available=available,
        model=settings.ollama_model,
        detail="" if available else "Ollama not reachable — run `ollama serve`.",
    )


@router.post("/explain", response_model=AiExplanationOut)
async def explain(
    req: ExplainRequest,
    force: bool = False,
    session: AsyncSession = Depends(get_session),
):
    """Return a plain-English explanation for a finding (cached when possible)."""
    try:
        return await ai_service.get_or_create_explanation(session, req, force=force)
    except ollama_client.OllamaError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Local LLM unavailable: {exc}. Start Ollama with "
                f"`ollama serve` and pull the model (`ollama pull "
                f"{settings.ollama_model}`)."
            ),
        )
