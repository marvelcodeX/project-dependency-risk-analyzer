import { useState, type ReactNode } from 'react'
import type { Finding } from '../lib/findings'
import type { DepGraph } from '../lib/graph'
import { pathTo } from '../lib/graph'
import { shortFix, upgradeCommand } from '../lib/fix'
import { isWebUrl } from '../lib/url'
import { reachabilityMeta } from '../severity'
import { AiExplanationPanel } from './AiExplanationPanel'

export function FindingDetail({
  finding,
  graph,
  aiAvailable,
}: {
  finding: Finding
  graph: DepGraph
  aiAvailable: boolean
}) {
  const { dep, vuln } = finding
  const [showAi, setShowAi] = useState(false)
  const path = graph.hasEdges ? pathTo(graph, `${dep.name}@${dep.version ?? ''}`) : null
  const fix = vuln.fixed_version ? upgradeCommand(dep, vuln.fixed_version) : null
  const reach = reachabilityMeta(vuln.reachability)
  // Advisory URLs are untrusted input: only ever link http(s).
  const refs = vuln.references.filter(isWebUrl)

  return (
    <div className="space-y-5 px-4 py-4 text-sm">
      <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-2 xl:grid-cols-3">
        <Fact label="Advisory">
          <a href={`https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">
            {vuln.id}
          </a>
          {vuln.aliases.length > 0 && (
            <div className="mt-0.5 flex flex-wrap gap-x-2 font-mono text-xs">
              {vuln.aliases.map((a) => <AliasLink key={a} id={a} />)}
            </div>
          )}
        </Fact>
        <Fact label="CVSS">
          {vuln.cvss_score !== null ? (
            <>
              <span className="font-semibold">{vuln.cvss_score}</span>
              {vuln.cvss_vector && <div className="mt-0.5 break-all font-mono text-xs text-muted">{vuln.cvss_vector}</div>}
            </>
          ) : (
            <span className="text-muted">Not scored</span>
          )}
        </Fact>
        <Fact label="Weakness (CWE)">
          {vuln.cwe_ids.length ? (
            <div className="flex flex-wrap gap-x-2">
              {vuln.cwe_ids.map((c) => (
                <a key={c} href={`https://cwe.mitre.org/data/definitions/${c.slice(4)}.html`} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">
                  {c}
                </a>
              ))}
            </div>
          ) : (
            <span className="text-muted">Not classified</span>
          )}
        </Fact>
        <Fact label="Exploitation">
          {vuln.in_cisa_kev ? 'Actively exploited (CISA KEV)' : vuln.has_public_exploit ? 'Public exploit / PoC available' : 'None known'}
        </Fact>
        <Fact label="Reachability">
          {reach.label}
          <div className="mt-0.5 text-xs text-muted">{reach.title}</div>
        </Fact>
        <Fact label="Version">
          <span className="font-mono">{dep.version ?? 'unspecified'}</span>
          <div className="mt-0.5 text-xs text-muted">
            {dep.version_source === 'latest'
              ? `Not pinned (${dep.raw_spec || 'no version'}) — scanned the latest release`
              : dep.pinned
                ? 'Exact pin'
                : dep.version
                  ? `Lower bound of ${dep.raw_spec}`
                  : 'No version — every advisory for the package is listed'}
          </div>
        </Fact>
      </dl>

      {(path || dep.direct !== null) && (
        <div>
          <SectionTitle>Why is this package here?</SectionTitle>
          {path && path.length > 1 ? (
            <ol className="flex flex-wrap items-center gap-1 font-mono text-xs text-ink-2">
              <li className="text-muted">your project</li>
              {path.map((k, i) => (
                <li key={k} className="flex items-center gap-1">
                  <span aria-hidden className="text-muted">→</span>
                  <span className={i === path.length - 1 ? 'font-semibold text-ink' : ''}>{k}</span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-ink-2">
              {dep.direct ? 'A direct dependency of your project.' : 'A transitive dependency (pulled in by another package); the manifest doesn’t record which one.'}
            </p>
          )}
        </div>
      )}

      <div>
        <SectionTitle>Fix</SectionTitle>
        {fix ? (
          <div className="space-y-1.5">
            <p className="text-ink-2">
              Fixed in <span className="font-mono text-ink">{shortFix(vuln.fixed_version!)}</span>.
            </p>
            {fix.kind === 'command' ? <CopyCommand text={fix.text} /> : <p className="text-ink-2">{fix.text}</p>}
          </div>
        ) : (
          <p className="text-ink-2">No patched version has been published. Consider an alternative package, or mitigate and monitor the advisory.</p>
        )}
      </div>

      {vuln.details && (
        <details>
          <summary className="cursor-pointer text-xs font-semibold tracking-wide text-ink-2 uppercase">Advisory details</summary>
          <p className="mt-2 max-h-64 overflow-y-auto whitespace-pre-line text-ink-2">{vuln.details}</p>
        </details>
      )}

      {refs.length > 0 && (
        <div>
          <SectionTitle>References</SectionTitle>
          <ul className="space-y-0.5 text-xs">
            {refs.map((r) => (
              <li key={r} className="truncate">
                <a href={r} target="_blank" rel="noreferrer" className="text-accent hover:underline">{r}</a>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="rounded-lg border border-line bg-surface-2">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5">
          <span className="text-xs font-semibold tracking-wide text-ink-2 uppercase">Plain-English explanation</span>
          {!showAi && (
            <button
              onClick={() => setShowAi(true)}
              disabled={!aiAvailable}
              title={aiAvailable ? 'Explain with the local LLM (nothing leaves your machine)' : 'Local LLM offline — start Ollama to enable'}
              className="rounded-md bg-accent px-3 py-1 text-xs font-semibold text-accent-ink transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Explain with AI
            </button>
          )}
        </div>
        {showAi && <AiExplanationPanel vuln={vuln} dep={dep} />}
      </div>
    </div>
  )
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-muted">{label}</dt>
      <dd className="m-0 mt-0.5 text-ink">{children}</dd>
    </div>
  )
}

function SectionTitle({ children }: { children: ReactNode }) {
  return <h4 className="mb-1.5 text-xs font-semibold tracking-wide text-ink-2 uppercase">{children}</h4>
}

function AliasLink({ id }: { id: string }) {
  const href = id.startsWith('CVE-')
    ? `https://nvd.nist.gov/vuln/detail/${id}`
    : id.startsWith('GHSA-')
      ? `https://github.com/advisories/${id}`
      : `https://osv.dev/vulnerability/${encodeURIComponent(id)}`
  return (
    <a href={href} target="_blank" rel="noreferrer" className="text-ink-2 hover:text-accent hover:underline">
      {id}
    </a>
  )
}

function CopyCommand({ text }: { text: string }) {
  const [copied, setCopied] = useState<'idle' | 'ok' | 'fail'>('idle')
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied('ok')
    } catch {
      setCopied('fail') // clipboard blocked: the command is still selectable
    }
    setTimeout(() => setCopied('idle'), 1500)
  }
  return (
    <div className="flex items-stretch overflow-hidden rounded-lg border border-line bg-page">
      <code className="min-w-0 flex-1 overflow-x-auto px-3 py-2 font-mono text-xs whitespace-pre text-ink select-all">{text}</code>
      <button onClick={copy} className="shrink-0 border-l border-line px-3 text-xs font-medium text-ink-2 transition hover:bg-surface-2">
        {copied === 'ok' ? 'Copied' : copied === 'fail' ? 'Select & copy' : 'Copy'}
      </button>
    </div>
  )
}
