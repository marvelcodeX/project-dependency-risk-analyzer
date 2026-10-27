# Soteria-AI 🛡️

**AI-Powered Dependency Risk Analyzer**

Soteria-AI scans your project's dependencies for known vulnerabilities and uses a local LLM to explain the risks in plain English — so you don't need to be a security expert to understand what's wrong and how to fix it.

## What Makes It Different

| Feature | Traditional Scanners | Soteria-AI |
|---------|---------------------|-----------|
| CVE detection | ✅ | ✅ |
| Plain-English explanations | ❌ Raw CVE text | ✅ AI-generated |
| Privacy | Cloud-based | ✅ Runs locally (Ollama) |
| Smart prioritization | CVSS only | ✅ CVSS + exploit status + reachability |
| Beginner-friendly | ❌ | ✅ Designed for developers, not security experts |

## Features

**Available now**

- 🔍 **Dependency Scanning** — Python `requirements.txt` (pins, ranges, extras, env markers, hashes), npm `package.json` / `package-lock.json` (full transitive tree), Go `go.mod` (with `replace`), Maven `pom.xml` (with `${property}` resolution). Format is auto-detected from the filename or content
- 🛡️ **Vulnerability Lookup** — Query the OSV database for known CVEs, with real CVSS scoring
- 🚨 **Exploited-in-the-Wild** — Cross-reference the CISA KEV catalog
- 🤖 **AI Explanations** — Local LLM (Ollama) explains each vulnerability in plain English
- 📊 **Smart Risk Scoring** — Composite 0–100 score from CVSS + KEV + reachability + fix availability
- 🌳 **Reachability Analysis** — Python-AST static analysis flags whether vulnerable PyPI packages are actually imported
- 💾 **Scan History** — Every scan is persisted and reloadable (SQLite by default, PostgreSQL-ready)
- 🖥️ **Web UI** — React dashboard: risk banner, severity tiles, findings table, history sidebar
- 📄 **Report Export** — JSON, SARIF 2.1.0 (GitHub code scanning), CycloneDX 1.5 SBOM with vulnerabilities, Markdown (PR comments), and a printable HTML report (Print → Save as PDF)
- ⚙️ **CI/CD** — CLI + GitHub Action that fails builds on a risk threshold and uploads SARIF; Docker image published to GHCR on release tags

**Planned**

- 📦 More ecosystems (`poetry.lock`, `Pipfile.lock`, `yarn.lock`, `Cargo.lock`, Gradle, …) and reachability for JS/Go/Java
- 🔬 NVD/CWE enrichment and function-level reachability
- 📈 Richer dashboard (charts, dependency-tree visualization)

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, SQLAlchemy (async) |
| Frontend | React, TypeScript, Tailwind CSS (Vite) |
| AI/LLM | Ollama (Mistral / Llama 3), local |
| Vuln Data | OSV API, CISA KEV *(NVD planned)* |
| Analysis | Python `ast` |
| Database | SQLite (dev) / PostgreSQL *(via `asyncpg`)* |

## Quick Start

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate      # macOS/Linux
# venv\Scripts\activate       # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Server runs at `http://localhost:8000` — API docs at `http://localhost:8000/docs`
(If port 8000 is taken, add `--port 8010` and update the proxy in `frontend/vite.config.ts`.)

### Frontend

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173
```

The dev server proxies `/api/*` to the backend on port 8000, so start the backend first.

### Run Tests

```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/file` | Upload a dependency file (+ optional `source_files` uploads) for scanning |
| `POST` | `/api/scan/text` | Submit file content as text for scanning (`filename: "pasted"` = auto-detect format) |
| `GET` | `/api/scans` | List saved scans (history), newest first |
| `GET` | `/api/scans/{id}` | Retrieve a saved scan by id |
| `GET` | `/api/scans/{id}/report?format=…` | Export a saved scan: `json` (default), `sarif`, `cyclonedx`, `markdown`, `html`; add `download=false` to view inline |
| `GET` | `/api/ai/status` | Whether the local LLM (Ollama) is reachable |
| `POST` | `/api/ai/explain` | Plain-English explanation for a finding (cached) |
| `GET` | `/api/health` | Health check |

Scans are persisted (SQLite by default; set `DATABASE_URL=postgresql+asyncpg://…` for
PostgreSQL). If OSV is unreachable the scan fails with `502` rather than reporting
"no vulnerabilities". Each finding is enriched with a **composite risk score (0–100)** built from
CVSS + CISA KEV (exploited-in-the-wild) + **reachability** + fix availability.

**Reachability:** pass your project's Python source with a scan (`source_files` on
`/api/scan/text`, or the "Add source" box in the UI) and Soteria-AI parses it with Python's
`ast` to check whether each vulnerable package is actually imported — findings are tagged
`REACHABLE` / `UNREACHABLE` / `POTENTIALLY_REACHABLE` / `UNKNOWN`, and unreachable ones are
deprioritized to cut noise.

## CI / CD

### GitHub Action

Scan any repository on every push/PR, upload findings to the **Security → Code scanning**
tab, add a Markdown report to the run summary, and fail the job above a risk threshold:

```yaml
# .github/workflows/soteria.yml
on: [push, pull_request]
permissions:
  contents: read
  security-events: write          # SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest        # Linux or macOS runners
    steps:
      - uses: actions/checkout@v5
      - uses: marvelcodeX/project-dependency-risk-analyzer@v0.4.0
        with:
          path: .                 # manifests or directories (space-separated)
          source: src             # optional: Python dirs for reachability
          fail-on: high           # critical | high | medium | low | none
```

Outputs: `risk-score`, `risk-level`, `findings`, `failed`, `sarif-file`. SARIF upload is
skipped automatically on pull requests from forks (no write token there).

### Command line

The same scanner runs anywhere (GitLab, Jenkins, pre-commit, locally). It needs only the
slim `requirements-cli.txt` and stores nothing:

```bash
pip install -r backend/requirements-cli.txt
PYTHONPATH=backend python -m app.cli scan . --source backend --fail-on high \
  -o sarif=soteria.sarif -o markdown=soteria.md -o cyclonedx=sbom.cdx.json
```

Directories are searched recursively for manifests, skipping `node_modules`, virtualenvs,
`.git`, `dist`/`build`, etc.; a `package.json` is skipped when a lockfile sits next to it.
`-o FORMAT=-` writes to stdout. Exit codes: **0** pass, **1** threshold met, **2** error
(including OSV being unreachable — a scan never silently passes).

### This repository's pipelines

| Workflow | Trigger | Does |
|---|---|---|
| `ci.yml` | push to `main`, PRs | backend tests (Python 3.11–3.13), CLI minimal-install check, frontend lint + build, Docker build + smoke test |
| `dependency-scan.yml` | push, PRs, weekly | scans this repo with the action (`fail-on: critical`) and uploads SARIF |
| `release.yml` | tag `vX.Y.Z` | checks the tag matches `app.__version__`, runs tests, pushes a multi-arch image to GHCR, creates a GitHub release |

To release: bump `__version__` in `backend/app/__init__.py`, commit, then
`git tag v0.4.0 && git push origin v0.4.0`.

### Docker

One image serves the API and the built UI on port 8000:

```bash
docker build -t soteria-ai .
docker run -p 8000:8000 -v soteria-data:/data soteria-ai
# or the published image:
docker run -p 8000:8000 -v soteria-data:/data ghcr.io/marvelcodex/project-dependency-risk-analyzer:latest
```

Data lives in the `/data` volume (SQLite). Use `-e DATABASE_URL=postgresql+asyncpg://…` for
Postgres and `-e OLLAMA_URL=http://host.docker.internal:11434` for AI explanations.

### Uploading an API scan to code scanning manually

```bash
curl -o soteria.sarif "http://localhost:8000/api/scans/<id>/report?format=sarif"
gh api repos/<owner>/<repo>/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" -f ref="refs/heads/main" \
  -f sarif="$(gzip -c soteria.sarif | base64)"   # on Linux: base64 -w0
```

### AI explanations (optional, local)

Plain-English explanations are generated by a **local LLM via [Ollama](https://ollama.com)** —
nothing leaves your machine. The app runs fine without it; AI features just report
"offline". To enable:

```bash
ollama serve                 # start the server
ollama pull mistral          # one-time model download (or set OLLAMA_MODEL)
```

Override defaults via env vars: `OLLAMA_URL` (default `http://localhost:11434`) and
`OLLAMA_MODEL` (default `mistral`).

## Project Status

> 🚧 **Work in Progress**
> - **Phase 1 (Foundation)** — ✅ parser + OSV lookup + CVSS scoring + React UI + persistence
> - **Phase 2 (Intelligence)** — ✅ CISA KEV enrichment, composite risk scoring, and local-LLM (Ollama) explanations done; live NVD/CWE enrichment optional/deferred
> - **Phase 3 (Reachability)** — ✅ Python AST import analysis; findings tagged reachable/unreachable and risk-scored accordingly
> - **Phase 4 (Multi-ecosystem)** — ✅ npm (`package.json`, `package-lock.json`), Go (`go.mod`), Maven (`pom.xml`); branch-aware fix versions; concurrent OSV lookups
> - **Phase 5 (Reports)** — ✅ JSON / SARIF / CycloneDX SBOM / Markdown / printable HTML export
> - **Phase 6 (CI/CD)** — ✅ CLI + GitHub Action (threshold gating, SARIF upload, job summary); CI, self-scan and GHCR release workflows; single Docker image
> - **Phase 7+ (richer dashboard, more ecosystems)** — not started


## License

MIT
