# Soteria-AI Backend

FastAPI service: manifest parsing → OSV lookup → enrichment (CISA KEV, CWE, exploits,
reachability) → risk scoring → persistence, plus reports, a CLI, and AI explanations.

## Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate    # macOS/Linux
# venv\Scripts\activate     # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Server runs at `http://localhost:8000` — interactive API docs at `http://localhost:8000/docs`.
Settings: copy `.env.example` to `.env` (database URL, Ollama URL/model, …).

## Database

SQLite by default (`soteria.db`); PostgreSQL via `DATABASE_URL=postgresql+asyncpg://…`.
**Alembic migrations run automatically on startup**, including upgrading databases created by
older versions. Manual commands:

```bash
alembic upgrade head          # apply migrations
alembic revision -m "..."     # new hand-written migration in migrations/versions/
```

## CLI

The scan pipeline also runs without the server or a database — for CI or local checks.
It only needs the slim `requirements-cli.txt`:

```bash
python -m app.cli scan PATH... [--source DIR] [-o FORMAT=FILE] [--fail-on LEVEL]
python -m app.cli scan . --source src --fail-on high -o sarif=soteria.sarif
```

Exit codes: `0` pass, `1` a finding met `--fail-on`, `2` error (including OSV unreachable).

## Tests

```bash
pytest -q       # fully offline — OSV, KEV, registries and Ollama are mocked
```

Notable guards: `test_migrations.py` (every historical database shape upgrades; models and
migrations agree) and `test_reports.py` (SARIF / CycloneDX validated against the official
schemas vendored in `tests/fixtures/schemas/`).

## Layout

```
app/
├── main.py            FastAPI app (+ serves the built UI when STATIC_DIR is set)
├── cli.py             python -m app.cli
├── api/               scan + report endpoints, AI endpoints
├── parsers/           requirements.txt, package.json/-lock, go.mod, pom.xml (+ detection)
├── services/          scanner (the pipeline), osv_client, registry, kev_client, cvss,
│                      versions, risk, reachability, store, ollama_client, ai
├── reports/           SARIF, CycloneDX, Markdown, HTML
├── models/ schemas/   ORM models / Pydantic schemas
└── core/              settings, database + migrations runner
migrations/            Alembic revisions
```
