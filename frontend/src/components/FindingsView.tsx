import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import type { Finding, Filters, SortKey } from '../lib/findings'
import {
  NO_FILTERS,
  REACHABILITIES,
  SEVERITIES,
  activeFilterCount,
  filterFindings,
  sortFindings,
} from '../lib/findings'
import type { DepGraph } from '../lib/graph'
import { shortFix } from '../lib/fix'
import type { LevelMeta } from '../severity'
import { TONE_BG, reachabilityMeta, severityMeta } from '../severity'
import { FindingDetail } from './FindingDetail'
import { Flag, ReachBadge, SeverityBadge } from './SeverityBadge'

const COLUMNS: { key: SortKey | null; label: string; className?: string }[] = [
  { key: 'risk', label: 'Risk' },
  { key: 'package', label: 'Package' },
  { key: 'severity', label: 'Severity' },
  { key: 'cvss', label: 'CVSS' },
  { key: 'advisory', label: 'Advisory' },
  { key: null, label: 'Summary', className: 'hidden lg:table-cell' },
  { key: null, label: 'Fix' },
]

export function FindingsView({
  findings,
  graph,
  aiAvailable,
  openKey,
}: {
  findings: Finding[]
  graph: DepGraph
  aiAvailable: boolean
  openKey: string | null
}) {
  const [filters, setFilters] = useState<Filters>(NO_FILTERS)
  const [sort, setSort] = useState<{ key: SortKey; dir: 'asc' | 'desc' }>({ key: 'risk', dir: 'desc' })
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(openKey ? [openKey] : []))
  const openRef = useRef<HTMLTableRowElement>(null)

  // Opening a finding from the overview: expand it and bring it into view.
  useEffect(() => {
    if (!openKey) return
    setFilters(NO_FILTERS)
    setExpanded((prev) => new Set(prev).add(openKey))
    requestAnimationFrame(() => openRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' }))
  }, [openKey])

  const ecosystems = useMemo(() => [...new Set(findings.map((f) => f.dep.ecosystem))].sort(), [findings])
  const rows = useMemo(
    () => sortFindings(filterFindings(findings, filters), sort.key, sort.dir),
    [findings, filters, sort],
  )
  const active = activeFilterCount(filters)

  function toggleRow(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  function toggleIn(field: 'severities' | 'reachability' | 'ecosystems', value: string) {
    setFilters((f) => {
      const set = new Set(f[field])
      if (set.has(value)) set.delete(value)
      else set.add(value)
      return { ...f, [field]: set }
    })
  }

  function sortBy(key: SortKey) {
    setSort((s) =>
      s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'package' || key === 'advisory' ? 'asc' : 'desc' },
    )
  }

  if (findings.length === 0) {
    return (
      <div className="rounded-xl border border-line bg-surface px-4 py-10 text-center text-sm text-ink-2">
        <span className="font-medium text-good-ink">No known vulnerabilities</span> in any dependency.
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {/* One filter row above everything it scopes */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-line bg-surface p-3">
        <input
          type="search"
          value={filters.query}
          onChange={(e) => setFilters((f) => ({ ...f, query: e.target.value }))}
          placeholder="Search package, CVE, CWE…"
          aria-label="Search findings"
          className="h-8 w-full rounded-lg border border-line bg-page px-3 text-sm text-ink outline-none placeholder:text-muted focus:border-accent sm:w-60"
        />
        <ChipGroup label="Severity">
          {SEVERITIES.map((s) => (
            <Chip key={s} pressed={filters.severities.has(s)} onClick={() => toggleIn('severities', s)} tone={severityMeta(s)}>
              {severityMeta(s).label}
            </Chip>
          ))}
        </ChipGroup>
        <ChipGroup label="Reachability">
          {REACHABILITIES.map((r) => (
            <Chip key={r} pressed={filters.reachability.has(r)} onClick={() => toggleIn('reachability', r)} tone={reachabilityMeta(r)}>
              {reachabilityMeta(r).label}
            </Chip>
          ))}
        </ChipGroup>
        {ecosystems.length > 1 && (
          <ChipGroup label="Ecosystem">
            {ecosystems.map((e) => (
              <Chip key={e} pressed={filters.ecosystems.has(e)} onClick={() => toggleIn('ecosystems', e)}>
                {e}
              </Chip>
            ))}
          </ChipGroup>
        )}
        <select
          value={filters.fix}
          onChange={(e) => setFilters((f) => ({ ...f, fix: e.target.value as Filters['fix'] }))}
          aria-label="Fix availability"
          className="h-8 rounded-lg border border-line bg-page px-2 text-xs text-ink"
        >
          <option value="any">Any fix status</option>
          <option value="available">Fix available</option>
          <option value="none">No fix yet</option>
        </select>
        <Chip pressed={filters.exploitedOnly} onClick={() => setFilters((f) => ({ ...f, exploitedOnly: !f.exploitedOnly }))}>
          Exploited only
        </Chip>
        {active > 0 && (
          <button onClick={() => setFilters(NO_FILTERS)} className="text-xs font-medium text-accent hover:underline">
            Clear {active}
          </button>
        )}
        <span className="ml-auto text-xs text-muted tabular-nums" aria-live="polite">
          {rows.length} of {findings.length}
        </span>
      </div>

      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-line text-xs text-muted">
              <tr>
                {COLUMNS.map((c) => (
                  <th
                    key={c.label}
                    aria-sort={c.key && sort.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}
                    className={`px-4 py-2.5 font-medium ${c.className ?? ''}`}
                  >
                    {c.key ? (
                      <button onClick={() => sortBy(c.key!)} className="inline-flex items-center gap-1 hover:text-ink">
                        {c.label}
                        <span aria-hidden className="w-2 text-ink-2">
                          {sort.key === c.key ? (sort.dir === 'asc' ? '↑' : '↓') : ''}
                        </span>
                      </button>
                    ) : (
                      c.label
                    )}
                  </th>
                ))}
                <th className="w-10 px-2" aria-label="Details" />
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => {
                const open = expanded.has(f.key)
                const cve = f.vuln.aliases.find((a) => a.startsWith('CVE-'))
                return (
                  <Fragment key={f.key}>
                    <tr
                      ref={f.key === openKey ? openRef : undefined}
                      onClick={() => toggleRow(f.key)}
                      className={`cursor-pointer border-b border-line align-top transition hover:bg-surface-2 ${open ? 'bg-surface-2' : ''}`}
                    >
                      <td className="px-4 py-3">
                        <div className="text-base font-semibold tabular-nums text-ink">{f.vuln.risk_score}</div>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {f.vuln.in_cisa_kev && <Flag title="Listed in CISA Known Exploited Vulnerabilities — exploited in the wild">KEV</Flag>}
                          {!f.vuln.in_cisa_kev && f.vuln.has_public_exploit && <Flag title="Public exploit / proof-of-concept code is referenced">PoC</Flag>}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-mono whitespace-nowrap text-ink">
                          {f.dep.name} <span className="text-muted">{f.dep.version ?? ''}</span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1.5">
                          {f.vuln.reachability !== 'UNKNOWN' && <ReachBadge reachability={f.vuln.reachability} />}
                          {f.dep.direct === false && <span className="text-xs text-muted">transitive{f.dep.depth !== null ? ` · depth ${f.dep.depth}` : ''}</span>}
                          {f.dep.version_source === 'latest' && <span className="text-xs text-muted" title="No version in the manifest — scanned the latest release">latest</span>}
                        </div>
                      </td>
                      <td className="px-4 py-3"><SeverityBadge severity={f.vuln.severity} /></td>
                      <td className="px-4 py-3 tabular-nums text-ink-2">{f.vuln.cvss_score ?? '—'}</td>
                      <td className="px-4 py-3 font-mono text-xs whitespace-nowrap text-ink-2">{cve ?? f.vuln.id}</td>
                      <td className="hidden max-w-md px-4 py-3 text-ink-2 lg:table-cell">{f.vuln.summary || '—'}</td>
                      <td className="px-4 py-3 font-mono text-xs whitespace-nowrap">
                        {f.vuln.fixed_version ? <span className="text-ink">{shortFix(f.vuln.fixed_version)}</span> : <span className="text-muted">none</span>}
                      </td>
                      <td className="px-2 py-3 text-center">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            toggleRow(f.key)
                          }}
                          aria-expanded={open}
                          aria-label={`${open ? 'Hide' : 'Show'} details for ${f.dep.name} ${f.vuln.id}`}
                          className="rounded p-1 text-ink-2 hover:bg-surface hover:text-ink"
                        >
                          <span aria-hidden className={`inline-block transition-transform ${open ? 'rotate-90' : ''}`}>›</span>
                        </button>
                      </td>
                    </tr>
                    {open && (
                      <tr className="border-b border-line bg-surface">
                        <td colSpan={COLUMNS.length + 1}>
                          <FindingDetail finding={f} graph={graph} aiAvailable={aiAvailable} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={COLUMNS.length + 1} className="px-4 py-10 text-center text-sm text-ink-2">
                    No findings match these filters.{' '}
                    <button onClick={() => setFilters(NO_FILTERS)} className="font-medium text-accent hover:underline">Clear filters</button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function ChipGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap items-center gap-1">
      {children}
    </div>
  )
}

function Chip({
  pressed,
  onClick,
  tone,
  children,
}: {
  pressed: boolean
  onClick: () => void
  tone?: LevelMeta
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      aria-pressed={pressed}
      className={`inline-flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-medium transition ${
        pressed ? 'border-accent bg-accent/10 text-ink' : 'border-line text-ink-2 hover:bg-surface-2 hover:text-ink'
      }`}
    >
      {tone && <span aria-hidden className={`h-2 w-2 rounded-full ${TONE_BG[tone.tone]}`} />}
      {children}
    </button>
  )
}
