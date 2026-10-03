import type { ReportFormat, ScanResponse } from '../api'
import { reportUrl } from '../api'
import { normalizeSeverity, riskTextClass } from '../severity'

interface Props {
  scan: ScanResponse
}

const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const

const EXPORTS: { format: ReportFormat; label: string; title: string }[] = [
  { format: 'json', label: 'JSON', title: 'Full scan result as JSON' },
  {
    format: 'sarif',
    label: 'SARIF',
    title: 'SARIF 2.1.0 — upload to GitHub code scanning',
  },
  {
    format: 'cyclonedx',
    label: 'SBOM',
    title: 'CycloneDX 1.5 SBOM with vulnerabilities',
  },
  {
    format: 'markdown',
    label: 'Markdown',
    title: 'Markdown summary for a PR comment or ticket',
  },
]

const COUNT_STYLES: Record<string, string> = {
  CRITICAL: 'text-rose-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-amber-400',
  LOW: 'text-sky-400',
  UNKNOWN: 'text-slate-400',
}

export function ScanSummary({ scan }: Props) {
  // Tally every vulnerability by normalized severity.
  const counts: Record<string, number> = {}
  let totalVulns = 0
  let kevCount = 0
  for (const r of scan.results) {
    for (const v of r.vulnerabilities) {
      const key = normalizeSeverity(v.severity)
      counts[key] = (counts[key] ?? 0) + 1
      totalVulns++
      if (v.in_cisa_kev) kevCount++
    }
  }

  return (
    <div className="space-y-3">
      {/* Overall project risk banner */}
      <div className="flex flex-wrap items-center gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-5 py-4">
        <div
          className={`text-4xl font-bold tabular-nums ${riskTextClass(
            scan.risk_level,
          )}`}
        >
          {scan.risk_score}
        </div>
        <div>
          <div className="text-sm font-semibold text-gray-200">
            Project risk score ·{' '}
            <span className={riskTextClass(scan.risk_level)}>
              {scan.risk_level}
            </span>
          </div>
          <div className="text-xs text-gray-500">
            Composite 0–100 · highest finding in this scan
            {kevCount > 0 && (
              <span className="ml-1 text-rose-400">
                · {kevCount} exploited in the wild (KEV)
              </span>
            )}
          </div>
        </div>
        {scan.id !== null && (
          <div className="ml-auto flex flex-wrap items-center justify-end gap-1.5 text-xs">
            <span className="mr-1 text-gray-500">Export</span>
            {EXPORTS.map((x) => (
              <a
                key={x.format}
                href={reportUrl(scan.id!, x.format)}
                download
                title={x.title}
                className="rounded-md border border-white/15 px-2 py-1 font-medium text-gray-300 transition hover:bg-white/5"
              >
                {x.label}
              </a>
            ))}
            <a
              href={reportUrl(scan.id, 'html', false)}
              target="_blank"
              rel="noopener noreferrer"
              title="Printable report — use your browser's Print → Save as PDF"
              className="rounded-md border border-violet-500/40 px-2 py-1 font-medium text-violet-300 transition hover:bg-violet-500/10"
            >
              Print / PDF
            </a>
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <Stat label="Dependencies" value={scan.total_dependencies} />
        <Stat label="Vulnerable" value={scan.vulnerable_dependencies} />
        <Stat label="Total CVEs" value={totalVulns} />
        {ORDER.map((sev) => (
          <Stat
            key={sev}
            label={sev.charAt(0) + sev.slice(1).toLowerCase()}
            value={counts[sev] ?? 0}
            valueClass={COUNT_STYLES[sev]}
          />
        ))}
      </div>
    </div>
  )
}

function Stat({
  label,
  value,
  valueClass = 'text-gray-100',
}: {
  label: string
  value: number
  valueClass?: string
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 text-left">
      <div className={`text-2xl font-semibold tabular-nums ${valueClass}`}>
        {value}
      </div>
      <div className="mt-0.5 text-xs font-medium uppercase tracking-wide text-gray-500">
        {label}
      </div>
    </div>
  )
}
