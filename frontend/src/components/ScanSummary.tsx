import type { ScanResponse } from '../api'
import { normalizeSeverity, riskTextClass } from '../severity'

interface Props {
  scan: ScanResponse
}

const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const

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
      <div className="flex items-center gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-5 py-4">
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
