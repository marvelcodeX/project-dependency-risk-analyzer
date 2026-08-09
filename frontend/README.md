# Soteria-AI Frontend

React + TypeScript + Tailwind CSS (Vite) UI for the dependency risk analyzer.

## Setup

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

The dev server proxies `/api/*` to the FastAPI backend at `http://localhost:8000`
(see `vite.config.ts`), so start the backend first. If your backend runs on a
different port, update the proxy target there.

## What it does

- Paste a `requirements.txt` (or upload a file) and scan it against the live OSV database
- Summary tiles: total deps, vulnerable deps, and CVE counts by severity
- Findings table sorted by severity, with CVSS score, advisory ID, summary, and fix version

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start the dev server |
| `npm run build` | Type-check (`tsc -b`) and build for production |
| `npm run preview` | Preview the production build |
| `npm run lint` | Run ESLint |
