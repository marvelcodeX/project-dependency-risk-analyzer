from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.ai import router as ai_router
from app.api.scan import router as scan_router
from app.core.config import settings
from app.core.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (dev convenience; use Alembic in production).
    await init_db()
    yield


app = FastAPI(
    title="Soteria-AI",
    description="AI-Powered Dependency Risk Analyzer",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api")
app.include_router(ai_router, prefix="/api")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": __version__}


# Serve the built UI last, so every /api route above takes precedence.
if settings.static_dir and Path(settings.static_dir).is_dir():
    app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="ui")
