# Contributing to Soteria-AI

Thanks for helping! Bug reports, new ecosystem parsers, and UI improvements are all welcome.
For security issues, see [SECURITY.md](SECURITY.md) instead of opening an issue.

## Development setup

Requirements: Python 3.11+, Node 22+. Ollama is optional (only for AI explanations).

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload          # http://localhost:8000 (API docs at /docs)

# Frontend (second terminal)
cd frontend
npm install
npm run dev                            # http://localhost:5173, proxies /api → :8000
```

Copy `backend/.env.example` to `backend/.env` to change settings (database, Ollama model, …).

## Checks — run before opening a PR

```bash
cd backend && pytest -q                       # fully offline: network calls are mocked
cd frontend && npm run lint && npm test && npm run build
```

CI runs the same checks (Python 3.11–3.13), builds the Docker image, and scans this repo's own
dependencies with the Soteria-AI GitHub Action.

## Conventions

- **Tests never touch the network.** Mock OSV/KEV/registries (see `tests/conftest.py` and
  `test_api.py` for the patterns). Pure frontend logic lives in `frontend/src/lib/` with
  Vitest tests next to it.
- **Database changes need a migration.** Add a hand-written Alembic revision under
  `backend/migrations/versions/` for every model change — `tests/test_migrations.py` fails
  if models and migrations disagree. Never edit a released migration.
- **One scan pipeline.** `app/services/scanner.py` is shared by the API and the CLI; put
  pipeline logic there, not in an endpoint.
- **Adding an ecosystem** touches: a parser in `app/parsers/` + its entries in
  `parsers/__init__.py` (`_PARSERS`, `FORMAT_ECOSYSTEMS`, `format_from_filename`),
  `reports/common.py` (`_PURL_TYPES`), optionally `services/registry.py` (unpinned
  versions) and `services/reachability.py` (source analysis), plus the `action.yml`
  description and README. CLI discovery, `GET /api/ecosystems` and the UI follow
  automatically.
- **UI colors come from design tokens** in `frontend/src/index.css` (`bg-surface`,
  `text-ink`, status tones…), never raw hex, so light and dark themes stay correct. Status
  colors always ship with a text label.
- **Reports must stay valid**: SARIF and CycloneDX output is checked against the official
  schemas in `backend/tests/fixtures/schemas/`.

## Pull requests

Keep PRs focused, describe *why* the change is needed, and add tests for behavior changes.
Update the README when you change user-facing behavior.
