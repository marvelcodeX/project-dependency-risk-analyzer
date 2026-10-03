import { useEffect, useState } from 'react'
import type { AiStatus, ScanResponse } from './api'
import { scanText, scanFile, getScan, aiStatus, MANIFEST_FORMATS } from './api'
import { ScanSummary } from './components/ScanSummary'
import { ResultsTable } from './components/ResultsTable'
import { ScanHistory } from './components/ScanHistory'

const SAMPLE = `flask==2.0.1
requests==2.25.0
django==3.1
numpy`

export default function App() {
  const [text, setText] = useState(SAMPLE)
  const [format, setFormat] = useState('pasted') // 'pasted' = auto-detect
  const [source, setSource] = useState('')
  const [showSource, setShowSource] = useState(false)
  const [scan, setScan] = useState<ScanResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [historyKey, setHistoryKey] = useState(0)
  const [ai, setAi] = useState<AiStatus | null>(null)

  useEffect(() => {
    aiStatus()
      .then(setAi)
      .catch(() => setAi({ available: false, model: '', detail: 'unreachable' }))
  }, [])

  async function run(promise: Promise<ScanResponse>, isNew = true) {
    setLoading(true)
    setError(null)
    try {
      setScan(await promise)
      if (isNew) setHistoryKey((k) => k + 1) // refresh the history list
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setScan(null)
    } finally {
      setLoading(false)
    }
  }

  function sourceFiles(): Record<string, string> {
    return source.trim() ? { 'pasted.py': source } : {}
  }

  function runTextScan() {
    void run(scanText(text, format, sourceFiles()))
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) void run(scanFile(file, sourceFiles()))
    e.target.value = '' // allow re-selecting the same file
  }

  return (
    <div className="mx-auto min-h-screen max-w-6xl px-4 py-8 sm:px-6">
      <header className="mb-8">
        <div className="flex items-center justify-between gap-3">
          <h1 className="flex items-center gap-2 text-2xl font-semibold text-gray-100">
            <span>🛡️</span> Soteria-AI
          </h1>
          {ai && (
            <span
              title={
                ai.available
                  ? `Local LLM ready (${ai.model})`
                  : ai.detail || 'Local LLM unavailable'
              }
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset ${
                ai.available
                  ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30'
                  : 'bg-slate-500/10 text-slate-400 ring-slate-500/30'
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  ai.available ? 'bg-emerald-400' : 'bg-slate-500'
                }`}
              />
              AI {ai.available ? `· ${ai.model}` : 'offline'}
            </span>
          )}
        </div>
        <p className="mt-1 text-sm text-gray-400">
          Paste or upload a dependency manifest —{' '}
          <code className="text-gray-300">requirements.txt</code>,{' '}
          <code className="text-gray-300">package.json</code>,{' '}
          <code className="text-gray-300">package-lock.json</code>,{' '}
          <code className="text-gray-300">go.mod</code> or{' '}
          <code className="text-gray-300">pom.xml</code> — to scan for known
          vulnerabilities (OSV).
        </p>
      </header>

      <section className="mb-6 rounded-xl border border-white/10 bg-white/[0.02] p-4">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          rows={7}
          className="w-full resize-y rounded-lg border border-white/10 bg-[#0b0e14] p-3 font-mono text-sm text-gray-200 outline-none focus:border-violet-500/60"
          placeholder="flask==2.0.1&#10;requests>=2.25.0"
        />
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button
            onClick={runTextScan}
            disabled={loading || !text.trim()}
            className="rounded-lg bg-violet-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? 'Scanning…' : 'Scan dependencies'}
          </button>

          <select
            value={format}
            onChange={(e) => setFormat(e.target.value)}
            aria-label="Manifest format"
            className="rounded-lg border border-white/15 bg-[#0b0e14] px-3 py-2 text-sm text-gray-300 outline-none focus:border-violet-500/60"
          >
            <option value="pasted">Auto-detect format</option>
            {MANIFEST_FORMATS.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>

          <label className="cursor-pointer rounded-lg border border-white/15 px-4 py-2 text-sm font-medium text-gray-300 transition hover:bg-white/5">
            Upload file
            <input
              type="file"
              accept=".txt,.text,.json,.mod,.xml,.pom"
              onChange={onFile}
              className="hidden"
            />
          </label>

          <button
            onClick={() => setShowSource((s) => !s)}
            className="text-xs text-violet-400 hover:underline"
          >
            {showSource ? '– Hide source' : '+ Add source for reachability'}
          </button>
        </div>

        {showSource && (
          <div className="mt-3">
            <textarea
              value={source}
              onChange={(e) => setSource(e.target.value)}
              spellCheck={false}
              rows={6}
              className="w-full resize-y rounded-lg border border-white/10 bg-[#0b0e14] p-3 font-mono text-sm text-gray-200 outline-none focus:border-violet-500/60"
              placeholder={'# Paste your Python source (optional)\n# Imports here decide which findings are reachable\nimport flask\nfrom requests import get'}
            />
            <p className="mt-1 text-xs text-gray-500">
              Pasted code is analyzed locally (AST) to flag which vulnerable
              packages your project actually imports. Applies to Python
              (PyPI) dependencies; other ecosystems show as unknown.
            </p>
          </div>
        )}
      </section>

      {error && (
        <div className="mb-6 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1fr_20rem]">
        <div className="min-w-0 space-y-6">
          {scan && (
            <>
              <ScanSummary scan={scan} />
              <ResultsTable scan={scan} aiAvailable={ai?.available ?? false} />
            </>
          )}
          {!scan && !error && !loading && (
            <p className="text-center text-sm text-gray-600">
              Results will appear here after a scan.
            </p>
          )}
        </div>

        <aside>
          <ScanHistory
            refreshKey={historyKey}
            activeId={scan?.id ?? null}
            onSelect={(id) => void run(getScan(id), false)}
          />
        </aside>
      </div>
    </div>
  )
}
