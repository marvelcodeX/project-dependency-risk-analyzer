# Single image: FastAPI backend serving the built React UI.
#   docker build -t soteria-ai .
#   docker run -p 8000:8000 -v soteria-data:/data soteria-ai
# Local LLM (optional): -e OLLAMA_URL=http://host.docker.internal:11434

# ---- frontend build ----------------------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- runtime -----------------------------------------------------------------
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATABASE_URL=sqlite+aiosqlite:////data/soteria.db \
    STATIC_DIR=/app/static \
    FRONTEND_ORIGIN=http://localhost:8000

WORKDIR /app
COPY backend/requirements.txt ./
# Runtime deps only: drop the test tooling listed under "Dev / test".
RUN sed -i '/^# Dev \/ test/,$d' requirements.txt \
    && pip install -r requirements.txt

COPY backend/app ./app
COPY --from=frontend /src/dist ./static

RUN useradd --system --uid 10001 --home-dir /app soteria \
    && mkdir -p /data && chown soteria /data
USER soteria
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
