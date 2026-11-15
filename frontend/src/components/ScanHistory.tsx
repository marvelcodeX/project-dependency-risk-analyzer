import type { ScanListItem } from '../api'
import { TONE_BG, riskMeta } from '../severity'

export function ScanHistory({
  items,
  activeId,
  onSelect,
}: {
  items: ScanListItem[]
  activeId: number | null
  onSelect: (id: number) => void
}) {
  if (items.length === 0) return null
  return (
    <nav aria-label="Recent scans" className="rounded-xl border border-line bg-surface">
      <h2 className="border-b border-line px-4 py-2.5 text-sm font-semibold text-ink">
        Recent scans <span className="font-normal text-muted">({items.length})</span>
      </h2>
      <ul className="max-h-[70vh] divide-y divide-line overflow-y-auto">
        {items.map((s) => {
          const meta = riskMeta(s.risk_level)
          return (
            <li key={s.id}>
              <button
                onClick={() => onSelect(s.id)}
                aria-current={s.id === activeId ? 'true' : undefined}
                className={`flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left text-sm transition hover:bg-surface-2 ${
                  s.id === activeId ? 'bg-surface-2' : ''
                }`}
              >
                <span className="min-w-0">
                  <span className="block truncate font-mono text-ink">{s.filename}</span>
                  <span className="text-xs text-muted">
                    {new Date(s.created_at).toLocaleString()} · {s.total_findings} findings
                  </span>
                </span>
                <span className="flex shrink-0 items-center gap-1.5" title={`Risk ${s.risk_level}`}>
                  <span aria-hidden className={`h-2 w-2 rounded-full ${TONE_BG[meta.tone]}`} />
                  <span className="text-sm font-semibold tabular-nums text-ink">{s.risk_score}</span>
                </span>
              </button>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
