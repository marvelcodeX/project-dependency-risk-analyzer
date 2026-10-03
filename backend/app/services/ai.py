"""AI explanation orchestration: cache lookup → generate → cache store."""

import hashlib

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.ai import AiExplanationCache
from app.schemas.ai import AiExplanation, AiExplanationOut, ExplainRequest
from app.services import ollama_client


def context_key(req: ExplainRequest) -> str:
    """Hash of everything the prompt depends on, plus the prompt version.

    Bump ``ollama_client.PROMPT_VERSION`` when the prompt changes so stale
    explanations aren't served.
    """
    blob = f"{ollama_client.PROMPT_VERSION}\n{req.model_dump_json()}"
    return hashlib.sha256(blob.encode()).hexdigest()


async def _get_cached(
    session: AsyncSession, vuln_id: str, model: str, ctx: str
) -> AiExplanationCache | None:
    result = await session.execute(
        select(AiExplanationCache).where(
            AiExplanationCache.vuln_id == vuln_id,
            AiExplanationCache.model == model,
            AiExplanationCache.context_key == ctx,
        )
    )
    return result.scalar_one_or_none()


async def get_or_create_explanation(
    session: AsyncSession, req: ExplainRequest, force: bool = False
) -> AiExplanationOut:
    """Return a cached explanation or generate (and cache) a new one.

    Raises ``OllamaError`` if generation is needed but the LLM is unavailable.
    """
    model = settings.ollama_model
    ctx = context_key(req)

    if not force:
        cached = await _get_cached(session, req.vuln_id, model, ctx)
        if cached is not None:
            return AiExplanationOut(
                summary=cached.summary,
                attack_scenario=cached.attack_scenario,
                project_impact=cached.project_impact,
                fix_steps=cached.fix_steps,
                priority=cached.priority,
                model=model,
                cached=True,
            )

    explanation: AiExplanation = await ollama_client.generate(req)
    await _store(session, req.vuln_id, model, ctx, explanation, replace=force)

    return AiExplanationOut(
        **explanation.model_dump(), model=model, cached=False
    )


async def _store(
    session: AsyncSession,
    vuln_id: str,
    model: str,
    ctx: str,
    exp: AiExplanation,
    replace: bool = False,
) -> None:
    """Persist an explanation, tolerating a concurrent insert of the same key.

    With ``replace`` (a forced regeneration) the existing row is updated, so
    the fresh explanation is what later requests get.
    """
    existing = await _get_cached(session, vuln_id, model, ctx) if replace else None
    if existing is not None:
        for field, value in exp.model_dump().items():
            setattr(existing, field, value)
        await session.commit()
        return
    row = AiExplanationCache(
        vuln_id=vuln_id, model=model, context_key=ctx, **exp.model_dump()
    )
    session.add(row)
    try:
        await session.commit()
    except IntegrityError:
        # Another request cached the same (vuln_id, model) first — that's fine.
        await session.rollback()
