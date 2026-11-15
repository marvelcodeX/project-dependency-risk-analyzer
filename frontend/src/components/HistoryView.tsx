import type { ScanListItem } from '../api'
import { ChartCard } from './charts/ChartCard'
import { TrendChart } from './charts/TrendChart'
import { RiskBadge } from './SeverityBadge'

/**
 * Trend of the project risk score across scans of the *same manifest* —
 * comparing unrelated files over time would be meaningless.
 */
export function HistoryView({
  filename,
  history,
  activeId,
  onSelect,
}: {
  filename: string
  history: ScanListItem[]
  activeId: number | null
  onSelect: (id: number) => void
}) {
  const scans = history
    .filter((s) => s.filename === filename)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())

  const points = scans.map((s) => ({
    id: s.id,
    date: new Date(s.created_at),
    value: s.risk_score,
    level: s.risk_level,
    findings: s.total_findings,
    vulnerable: s.vulnerable_dependencies,
    total: s.total_dependencies,
  }))

  const first = scans[0]
  const last = scans[scans.length - 1]
  const delta = scans.length > 1 ? last.risk_score - first.risk_score : null

  return (
    <ChartCard
      title={`Risk over time · ${filename}`}
      caption={
        scans.length < 2
          ? 'Scan this manifest again after changes to see a trend.'
          : `${scans.length} scans · risk ${delta! > 0 ? 'up' : delta! < 0 ? 'down' : 'unchanged'}${delta ? ` ${Math.abs(delta)} points` : ''} since the first`
      }
      table={
        <div className="overflow-x-auto">
          <table className="w-full min-w-[520px] text-left text-sm">
            <thead>
              <tr className="border-b border-line text-xs text-muted">
                <th className="py-1.5 font-medium">Scanned</th>
                <th className="py-1.5 text-right font-medium">Risk</th>
                <th className="py-1.5 pl-3 font-medium">Level</th>
                <th className="py-1.5 text-right font-medium">Findings</th>
                <th className="py-1.5 text-right font-medium">Vulnerable</th>
              </tr>
            </thead>
            <tbody>
              {[...scans].reverse().map((s) => (
                <tr
                  key={s.id}
                  onClick={() => onSelect(s.id)}
                  className={`cursor-pointer border-b border-line last:border-0 hover:bg-surface-2 ${s.id === activeId ? 'bg-surface-2' : ''}`}
                >
                  <td className="py-1.5 text-ink">{new Date(s.created_at).toLocaleString()}</td>
                  <td className="py-1.5 text-right tabular-nums text-ink">{s.risk_score}</td>
                  <td className="py-1.5 pl-3"><RiskBadge level={s.risk_level} /></td>
                  <td className="py-1.5 text-right tabular-nums text-ink">{s.total_findings}</td>
                  <td className="py-1.5 text-right tabular-nums text-ink">{s.vulnerable_dependencies}/{s.total_dependencies}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      }
    >
      <TrendChart points={points} activeId={activeId} onSelect={onSelect} />
    </ChartCard>
  )
}
