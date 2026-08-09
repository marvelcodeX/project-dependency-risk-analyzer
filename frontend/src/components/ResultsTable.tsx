import { useMemo, useState } from 'react'
import type { Dependency, ScanResponse, Vulnerability } from '../api'
import { reachabilityMeta, riskTextClass } from '../severity'
import { SeverityBadge } from './SeverityBadge'
import { AiExplanationPanel } from './AiExplanationPanel'

interface Row {
  key: string
  pkg: string
  dep: Dependency
  version: string | null
  pinned: boolean
  vuln: Vulnerability
}

const COLSPAN = 8

export function ResultsTable({
  scan,
  aiAvailable,
}: {
  scan: ScanResponse
  aiAvailable: boolean
}) {
  const [onlyVulnerable, setOnlyVulnerable] = useState(true)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  // Flatten to one row per vulnerability, highest composite risk first.
  const rows = useMemo<Row[]>(() => {
    const out: Row[] = []
    for (const r of scan.results) {
      for (const v of r.vulnerabilities) {
        out.push({
          key: `${r.dependency.name}-${v.id}`,
          pkg: r.dependency.name,
          dep: r.dependency,
          version: r.dependency.version,
          pinned: r.dependency.pinned,
          vuln: v,
        })
      }
    }
    out.sort(
      (a, b) =>
        b.vuln.risk_score - a.vuln.risk_score ||
        (b.vuln.cvss_score ?? 0) - (a.vuln.cvss_score ?? 0),
    )
    return out
  }, [scan])

  const cleanDeps = scan.results.filter((r) => r.vulnerabilities.length === 0)

  return (
    <div className="overflow-hidden rounded-xl border border-white/10">
      <div className="flex items-center justify-between border-b border-white/10 bg-white/[0.02] px-4 py-2.5">
        <h2 className="text-sm font-semibold text-gray-200">
          Findings <span className="text-gray-500">({rows.length})</span>
        </h2>
        <label className="flex items-center gap-2 text-xs text-gray-400">
          <input
            type="checkbox"
            checked={onlyVulnerable}
            onChange={(e) => setOnlyVulnerable(e.target.checked)}
            className="accent-violet-500"
          />
          Hide clean dependencies
        </label>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[900px] text-left text-sm">
          <thead className="bg-white/[0.02] text-xs uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-4 py-2.5 font-medium">Risk</th>
              <th className="px-4 py-2.5 font-medium">Package</th>
              <th className="px-4 py-2.5 font-medium">Severity</th>
              <th className="px-4 py-2.5 font-medium">CVSS</th>
              <th className="px-4 py-2.5 font-medium">Advisory</th>
              <th className="px-4 py-2.5 font-medium">Summary</th>
              <th className="px-4 py-2.5 font-medium">Fix</th>
              <th className="px-4 py-2.5 font-medium">AI</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {rows.map((row) => (
              <VulnRow
                key={row.key}
                row={row}
                aiAvailable={aiAvailable}
                isExpanded={expanded.has(row.key)}
                onToggle={() => toggle(row.key)}
              />
            ))}

            {!onlyVulnerable &&
              cleanDeps.map((r) => (
                <tr key={`clean-${r.dependency.name}`} className="text-gray-500">
                  <td className="px-4 py-2.5" />
                  <td className="px-4 py-2.5 font-mono text-gray-300">
                    {r.dependency.name}
                    <span className="text-gray-500">
                      {r.dependency.version ? ` ${r.dependency.version}` : ''}
                    </span>
                  </td>
                  <td className="px-4 py-2.5" colSpan={6}>
                    <span className="text-emerald-400">
                      ✓ No known vulnerabilities
                    </span>
                  </td>
                </tr>
              ))}

            {rows.length === 0 && onlyVulnerable && (
              <tr>
                <td
                  colSpan={COLSPAN}
                  className="px-4 py-10 text-center text-emerald-400"
                >
                  ✓ No known vulnerabilities found in any dependency.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function VulnRow({
  row,
  aiAvailable,
  isExpanded,
  onToggle,
}: {
  row: Row
  aiAvailable: boolean
  isExpanded: boolean
  onToggle: () => void
}) {
  const { vuln } = row
  const cveAlias = vuln.aliases.find((a) => a.startsWith('CVE-'))
  const link = vuln.references[0]
  return (
    <>
    <tr className="align-top hover:bg-white/[0.02]">
      <td className="px-4 py-3">
        <div className="flex items-baseline gap-1.5">
          <span
            className={`text-lg font-semibold tabular-nums ${riskTextClass(
              vuln.risk_level,
            )}`}
          >
            {vuln.risk_score}
          </span>
          <span className="text-[10px] uppercase text-gray-500">
            {vuln.risk_level}
          </span>
        </div>
        {vuln.in_cisa_kev && (
          <span
            className="mt-1 inline-flex items-center rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-rose-300 ring-1 ring-inset ring-rose-500/40"
            title="Listed in the CISA Known Exploited Vulnerabilities catalog — exploited in the wild"
          >
            KEV
          </span>
        )}
      </td>
      <td className="px-4 py-3 whitespace-nowrap">
        <div className="font-mono text-gray-200">
          {row.pkg}
          <span className="text-gray-500">
            {row.version ? ` ${row.version}` : ''}
          </span>
          {!row.pinned && row.version && (
            <span
              className="ml-2 text-xs text-amber-500/80"
              title="Version not pinned with =="
            >
              unpinned
            </span>
          )}
        </div>
        {vuln.reachability !== 'UNKNOWN' && (
          <ReachBadge reachability={vuln.reachability} />
        )}
      </td>
      <td className="px-4 py-3">
        <SeverityBadge severity={vuln.severity} />
      </td>
      <td className="px-4 py-3 tabular-nums text-gray-300">
        {vuln.cvss_score ?? '—'}
      </td>
      <td className="px-4 py-3 whitespace-nowrap">
        <span className="font-mono text-xs text-gray-300">
          {cveAlias ?? vuln.id}
        </span>
      </td>
      <td className="max-w-md px-4 py-3 text-gray-400">{vuln.summary || '—'}</td>
      <td className="px-4 py-3 whitespace-nowrap">
        {vuln.fixed_version ? (
          <span className="font-mono text-xs text-emerald-400">
            {formatFix(vuln.fixed_version)}
          </span>
        ) : (
          <span className="text-gray-600">none</span>
        )}
        {link && (
          <a
            href={link}
            target="_blank"
            rel="noreferrer"
            className="ml-2 text-xs text-violet-400 hover:underline"
          >
            details ↗
          </a>
        )}
      </td>
      <td className="px-4 py-3 whitespace-nowrap">
        <button
          onClick={onToggle}
          disabled={!aiAvailable}
          title={
            aiAvailable
              ? 'Explain this vulnerability in plain English (local LLM)'
              : 'Local LLM unavailable — start Ollama to enable AI explanations'
          }
          className="rounded-md border border-violet-500/40 px-2.5 py-1 text-xs font-medium text-violet-300 transition hover:bg-violet-500/10 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {isExpanded ? 'Hide' : '✨ Explain'}
        </button>
      </td>
    </tr>
    {isExpanded && (
      <tr>
        <td colSpan={COLSPAN} className="border-t border-white/5 bg-violet-500/[0.03]">
          <AiExplanationPanel vuln={vuln} dep={row.dep} />
        </td>
      </tr>
    )}
    </>
  )
}

function ReachBadge({ reachability }: { reachability: string }) {
  const m = reachabilityMeta(reachability)
  return (
    <span
      title={m.title}
      className={`mt-1 inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ring-1 ring-inset ${m.cls}`}
    >
      {m.label}
    </span>
  )
}

// OSV sometimes reports a git commit hash as the "fixed" event; show a short form.
function formatFix(fix: string): string {
  if (/^[0-9a-f]{40}$/i.test(fix)) return fix.slice(0, 7)
  return fix
}
