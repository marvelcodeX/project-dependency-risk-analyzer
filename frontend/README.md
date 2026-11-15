# Soteria-AI Frontend

React + TypeScript + Tailwind CSS (Vite) dashboard for the dependency risk analyzer.

## Setup

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

The dev server proxies `/api/*` to the FastAPI backend at `http://localhost:8000`
(see `vite.config.ts`), so start the backend first. If your backend runs on another port,
update the proxy target — or build the UI and let the backend serve it
(`npm run build`, then `STATIC_DIR=../frontend/dist uvicorn app.main:app` in `backend/`).

## What it does

- **Scan:** paste or upload a manifest (format auto-detected; the supported list comes from
  `GET /api/ecosystems`), optionally with Python / JS / TS source for reachability
- **Overview:** risk score + meter, KPI tiles, findings by severity and by reachability,
  most urgent findings
- **Findings:** search, filter (severity, reachability, ecosystem, fix, exploitation), sort;
  each row opens a detail view — CWE, exploit status, dependency path, copyable fix command,
  and an on-demand AI explanation from the local LLM
- **Dependencies:** tree from the lockfile graph, focused on paths to vulnerable packages
- **History:** risk trend across scans of the same manifest
- **Export:** JSON, SARIF, CycloneDX SBOM, Markdown, printable HTML
- Light / dark / auto theme; every chart has a table view

## Structure

```
src/
├── index.css        design tokens (light + dark) — components never use raw colors
├── api.ts           typed client mirroring the backend schemas
├── severity.ts      severity / risk / reachability → status tone + label
├── lib/             pure logic (filtering, sorting, graph paths, fix commands) + Vitest tests
├── hooks/           useTheme, useWidth
└── components/      Overview, FindingsView, FindingDetail, DependencyTree, HistoryView,
                     charts/ (ChartCard, SegmentedBar, Meter, TrendChart), …
```

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start the dev server |
| `npm run build` | Type-check (`tsc -b`) and build for production |
| `npm test` | Run the logic tests (Vitest) |
| `npm run lint` | Lint with oxlint |
| `npm run preview` | Preview the production build |
