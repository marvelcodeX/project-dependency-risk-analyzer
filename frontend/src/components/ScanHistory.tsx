import { useEffect, useState } from 'react'
import type { ScanListItem } from '../api'
import { listScans } from '../api'
import { riskTextClass } from '../severity'

interface Props {
  // Bumping this value triggers a reload (e.g. after a new scan completes).
  refreshKey: number
  activeId: number | null
  onSelect: (id: number) => void
}

export function ScanHistory({ refreshKey, activeId, onSelect }: Props) {
  const [items, setItems] = useState<ScanListItem[]>([])

  useEffect(() => {
    listScans()
      .then(setItems)
      .catch(() => setItems([]))
  }, [refreshKey])

  if (items.length === 0) return null

  return (
    <div className="rounded-xl border border-white/10">
      <h2 className="border-b border-white/10 bg-white/[0.02] px-4 py-2.5 text-sm font-semibold text-gray-200">
        Recent scans <span className="text-gray-500">({items.length})</span>
      </h2>
      <ul className="divide-y divide-white/5">
        {items.map((s) => (
          <li key={s.id}>
            <button
              onClick={() => onSelect(s.id)}
              className={`flex w-full items-center justify-between px-4 py-2.5 text-left text-sm transition hover:bg-white/[0.03] ${
                s.id === activeId ? 'bg-white/[0.04]' : ''
              }`}
            >
              <span className="min-w-0">
                <span className="block truncate font-mono text-gray-300">
                  {s.filename}
                </span>
                <span className="text-xs text-gray-500">
                  {new Date(s.created_at).toLocaleString()} ·{' '}
                  {s.vulnerable_dependencies}/{s.total_dependencies} vulnerable
                </span>
              </span>
              <span
                className={`ml-3 shrink-0 text-sm font-semibold tabular-nums ${riskTextClass(
                  s.risk_level,
                )}`}
                title={`Risk ${s.risk_level}`}
              >
                {s.risk_score}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
