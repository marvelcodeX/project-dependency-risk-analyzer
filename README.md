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

- 🔍 **Dependency Scanning** — Parse `requirements.txt`, `package.json`, `pom.xml`, and more
- 🛡️ **Vulnerability Lookup** — Query OSV & NVD databases for known CVEs
- 🤖 **AI Explanations** — Local LLM explains each vulnerability in plain English
- 📊 **Smart Risk Scoring** — Composite score based on CVSS, exploit availability, and reachability
- 🌳 **Reachability Analysis** — AST-based static analysis to check if vulnerable code is actually used
- 📈 **Web Dashboard** — Interactive charts, dependency tree visualization, severity heatmaps
- 📄 **Reports** — Export PDF, JSON, SARIF, and CycloneDX SBOM

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI |
| Frontend | React, TypeScript, Tailwind CSS |
| AI/LLM | Ollama (Mistral / Llama 3) |
| Vuln Data | OSV API, NVD API, CISA KEV |
| Analysis | Python AST, tree-sitter |
| Database | PostgreSQL, SQLAlchemy |

## Quick Start

### Backend

```bash
cd Soteria-AI/backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Server runs at `http://localhost:8000` — API docs at `http://localhost:8000/docs`

### Run Tests

```bash
cd Soteria-AI/backend
venv\Scripts\activate
pytest tests/ -v
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/file` | Upload a dependency file for scanning |
| `POST` | `/api/scan/text` | Submit file content as text for scanning |
| `GET` | `/api/health` | Health check |

## Project Status

> 🚧 **Work in Progress** — Phase 1 of 6


## License

MIT
