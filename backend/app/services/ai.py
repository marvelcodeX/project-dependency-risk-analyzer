"""AI explanation orchestration: cache lookup → generate → cache store."""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.ai import AiExplanationCache
from app.schemas.ai import AiExplanation, AiExplanationOut, ExplainRequest
from app.services import ollama_client


async def _get_cached(
    session: AsyncSession, vuln_id: str, model: str
) -> AiExplanationCache | None:
    result = await session.execute(
        select(AiExplanationCache).where(
            AiExplanationCache.vuln_id == vuln_id,
            AiExplanationCache.model == model,
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

    if not force:
        cached = await _get_cached(session, req.vuln_id, model)
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
    await _store(session, req.vuln_id, model, explanation)

    return AiExplanationOut(
        **explanation.model_dump(), model=model, cached=False
    )


async def _store(
    session: AsyncSession, vuln_id: str, model: str, exp: AiExplanation
) -> None:
    """Persist an explanation, tolerating a concurrent insert of the same key."""
    row = AiExplanationCache(vuln_id=vuln_id, model=model, **exp.model_dump())
    session.add(row)
    try:
        await session.commit()
    except IntegrityError:
        # Another request cached the same (vuln_id, model) first — that's fine.
        await session.rollback()
