import { useCallback, useEffect, useMemo, useState } from 'react'
import type { AiStatus, ManifestFormat, ReportFormat, ScanListItem, ScanResponse } from './api'
import { FALLBACK_FORMATS, aiStatus, getScan, listFormats, listScans, reportUrl, scanFile, scanText } from './api'
import { DependencyTree } from './components/DependencyTree'
import { FindingsView } from './components/FindingsView'
import { HistoryView } from './components/HistoryView'
import { Overview } from './components/Overview'
import { ScanHistory } from './components/ScanHistory'
import { ThemeToggle } from './components/ThemeToggle'
import { useTheme } from './hooks/useTheme'
import { flattenFindings } from './lib/findings'
import { buildGraph } from './lib/graph'

const SAMPLE = `flask==2.0.1
requests==2.25.0
django==3.1
numpy`

type Tab = 'overview' | 'findings' | 'dependencies' | 'history'

const EXPORTS: { format: ReportFormat; label: string; title: string }[] = [
  { format: 'json', label: 'JSON', title: 'Full scan result as JSON' },
  { format: 'sarif', label: 'SARIF', title: 'SARIF 2.1.0 — upload to GitHub code scanning' },
  { format: 'cyclonedx', label: 'SBOM', title: 'CycloneDX 1.5 SBOM with vulnerabilities and dependency graph' },
  { format: 'markdown', label: 'Markdown', title: 'Markdown summary for a PR comment or ticket' },
]

export default function App() {
  const [theme, setTheme] = useTheme()
  const [text, setText] = useState(SAMPLE)
  const [format, setFormat] = useState('pasted') // 'pasted' = auto-detect
  const [formats, setFormats] = useState<ManifestFormat[]>(FALLBACK_FORMATS)
  const [source, setSource] = useState('')
  const [showSource, setShowSource] = useState(false)
  const [scan, setScan] = useState<ScanResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<ScanListItem[]>([])
  const [ai, setAi] = useState<AiStatus | null>(null)
  const [tab, setTab] = useState<Tab>('overview')
  const [openKey, setOpenKey] = useState<string | null>(null)

  const refreshHistory = useCallback(() => {
    listScans().then(setHistory).catch(() => setHistory([]))
  }, [])

  useEffect(() => {
    aiStatus()
      .then(setAi)
      .catch(() => setAi({ available: false, model: '', detail: 'unreachable' }))
    listFormats().then(setFormats).catch(() => {}) // keep the fallback list
    refreshHistory()
  }, [refreshHistory])

  const findings = useMemo(() => (scan ? flattenFindings(scan) : []), [scan])
  const graph = useMemo(() => (scan ? buildGraph(scan) : null), [scan])

  async function run(promise: Promise<ScanResponse>, isNew = true) {
    setLoading(true)
    setError(null)
    try {
      setScan(await promise)
      setOpenKey(null)
      if (isNew) {
        setTab('overview')
        refreshHistory()
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  function sourceFiles(): Record<string, string> {
    // Extensionless: the backend tries Python first, then JavaScript/TypeScript.
    return source.trim() ? { pasted: source } : {}
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) void run(scanFile(file, sourceFiles()))
    e.target.value = '' // allow re-selecting the same file
  }

  function openFinding(key: string) {
    setOpenKey(key)
    setTab('findings')
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'findings', label: `Findings (${findings.length})` },
    { id: 'dependencies', label: 'Dependencies' },
    { id: 'history', label: 'History' },
  ]

  return (
    <div className="mx-auto min-h-screen max-w-7xl px-4 py-6 sm:px-6">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-ink">Soteria-AI</h1>
          <p className="text-xs text-ink-2">Dependency risk analysis · runs locally</p>
        </div>
        <div className="flex items-center gap-3">
          {ai && (
            <span
              title={ai.available ? `Local LLM ready (${ai.model})` : ai.detail || 'Local LLM unavailable'}
              className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 text-xs text-ink-2"
            >
              <span aria-hidden className={`h-2 w-2 rounded-full ${ai.available ? 'bg-good' : 'bg-unknown'}`} />
              AI {ai.available ? `· ${ai.model}` : 'offline'}
            </span>
          )}
          <ThemeToggle theme={theme} onChange={setTheme} />
        </div>
      </header>

      <section aria-label="New scan" className="mb-6 rounded-xl border border-line bg-surface p-4">
        <label htmlFor="manifest" className="mb-1.5 block text-xs font-medium text-ink-2">
          Paste a manifest — {formats.map((f) => f.format).join(', ')}
        </label>
        <textarea
          id="manifest"
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          rows={6}
          className="w-full resize-y rounded-lg border border-line bg-page p-3 font-mono text-sm text-ink outline-none focus:border-accent"
          placeholder={'flask==2.0.1\nrequests>=2.25.0'}
        />
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            onClick={() => void run(scanText(text, format, sourceFiles()))}
            disabled={loading || !text.trim()}
            className="h-9 rounded-lg bg-accent px-4 text-sm font-semibold text-accent-ink transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? 'Scanning…' : 'Scan dependencies'}
          </button>
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value)}
            aria-label="Manifest format"
            className="h-9 rounded-lg border border-line bg-page px-2 text-sm text-ink"
          >
            <option value="pasted">Auto-detect format</option>
            {formats.map((f) => (
              <option key={f.format} value={f.format}>
                {f.format} ({f.ecosystem})
              </option>
            ))}
          </select>
          <label className="inline-flex h-9 cursor-pointer items-center rounded-lg border border-line px-4 text-sm font-medium text-ink-2 transition hover:bg-surface-2 focus-within:outline-2 focus-within:outline-accent">
            Upload file
            <input type="file" accept=".txt,.text,.json,.mod,.xml,.pom" onChange={onFile} className="sr-only" />
          </label>
          <button
            onClick={() => setShowSource((s) => !s)}
            aria-expanded={showSource}
            className="text-xs font-medium text-accent hover:underline"
          >
            {showSource ? 'Hide source' : 'Add source for reachability'}
          </button>
        </div>
        {showSource && (
          <div className="mt-3">
            <textarea
              value={source}
              onChange={(e) => setSource(e.target.value)}
              spellCheck={false}
              rows={6}
              aria-label="Project source code for reachability analysis"
              className="w-full resize-y rounded-lg border border-line bg-page p-3 font-mono text-sm text-ink outline-none focus:border-accent"
              placeholder={'# Paste Python or JavaScript/TypeScript source (optional)\n# Imports here decide which findings are reachable\nimport flask\nimport express from "express"'}
            />
            <p className="mt-1 text-xs text-muted">
              Analyzed locally: Python imports for PyPI packages, JS/TS imports for npm. Supported for{' '}
              {formats.filter((f) => f.reachability).map((f) => f.format).join(', ')}.
            </p>
          </div>
        )}
      </section>

      {error && (
        <div role="alert" className="mb-6 flex items-start gap-2 rounded-xl border border-critical/50 bg-surface px-4 py-3 text-sm text-ink">
          <span aria-hidden className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-critical" />
          {error}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
        <main className={`min-w-0 transition-opacity ${loading && scan ? 'opacity-60' : ''}`}>
          {scan && graph ? (
            <>
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <h2 className="truncate font-mono text-sm font-semibold text-ink">{scan.filename}</h2>
                  {scan.created_at && (
                    <p className="text-xs text-muted">Scanned {new Date(scan.created_at).toLocaleString()}</p>
                  )}
                </div>
                {scan.id !== null && (
                  <div className="flex flex-wrap items-center gap-1.5 text-xs">
                    <span className="mr-1 text-muted">Export</span>
                    {EXPORTS.map((x) => (
                      <a
                        key={x.format}
                        href={reportUrl(scan.id!, x.format)}
                        download
                        title={x.title}
                        className="rounded-md border border-line bg-surface px-2 py-1 font-medium text-ink-2 transition hover:bg-surface-2 hover:text-ink"
                      >
                        {x.label}
                      </a>
                    ))}
                    <a
                      href={reportUrl(scan.id, 'html', false)}
                      target="_blank"
                      rel="noopener noreferrer"
                      title="Printable report — use your browser's Print → Save as PDF"
                      className="rounded-md border border-accent/50 bg-surface px-2 py-1 font-medium text-ink transition hover:bg-accent/10"
                    >
                      Print / PDF
                    </a>
                  </div>
                )}
              </div>

              <div role="tablist" aria-label="Scan views" className="mb-4 flex gap-1 overflow-x-auto border-b border-line">
                {tabs.map((t) => (
                  <button
                    key={t.id}
                    role="tab"
                    id={`tab-${t.id}`}
                    aria-selected={tab === t.id}
                    aria-controls={`panel-${t.id}`}
                    onClick={() => setTab(t.id)}
                    className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap transition ${
                      tab === t.id ? 'border-accent text-ink' : 'border-transparent text-ink-2 hover:text-ink'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
                {tab === 'overview' && <Overview scan={scan} findings={findings} onOpenFinding={openFinding} />}
                {tab === 'findings' && (
                  <FindingsView findings={findings} graph={graph} aiAvailable={ai?.available ?? false} openKey={openKey} />
                )}
                {tab === 'dependencies' && <DependencyTree graph={graph} onOpenFinding={openFinding} />}
                {tab === 'history' && (
                  <HistoryView
                    filename={scan.filename}
                    history={history}
                    activeId={scan.id}
                    onSelect={(id) => void run(getScan(id), false)}
                  />
                )}
              </div>
            </>
          ) : (
            !error &&
            !loading && (
              <div className="rounded-xl border border-dashed border-line px-6 py-12 text-center">
                <p className="text-sm font-medium text-ink">No scan loaded</p>
                <p className="mt-1 text-sm text-ink-2">
                  Scan the sample above, paste your own manifest, or open a recent scan.
                </p>
              </div>
            )
          )}
          {loading && !scan && (
            <p role="status" className="py-12 text-center text-sm text-ink-2">
              Scanning dependencies…
            </p>
          )}
        </main>

        <aside>
          <ScanHistory items={history} activeId={scan?.id ?? null} onSelect={(id) => void run(getScan(id), false)} />
        </aside>
      </div>
    </div>
  )
}
