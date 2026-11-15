import { useState } from 'react'
import { useWidth } from '../../hooks/useWidth'
import type { LevelMeta } from '../../severity'
import { TONE_BG } from '../../severity'

export interface Part {
  key: string
  meta: LevelMeta
  count: number
  title?: string
}

const GAP = 2 // px surface gap between blocks
const CHAR_PX = 7.5 // rough width of a 12px semibold digit
const PAD_PX = 16

/**
 * Tall segmented bar (one whole split into ≤6 parts). Each part's count is
 * printed inside its block only when it fits; hover / keyboard focus shows
 * name, count and share; the legend names the parts in block order and adds
 * the count for any block too narrow to print it.
 */
export function SegmentedBar({ parts, unit }: { parts: Part[]; unit: string }) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const [active, setActive] = useState<string | null>(null)
  const total = parts.reduce((s, p) => s + p.count, 0)
  const visible = parts.filter((p) => p.count > 0)

  if (total === 0) {
    return <p className="py-3 text-sm text-muted">No {unit} to break down.</p>
  }

  const usable = Math.max(0, width - GAP * (visible.length - 1))
  const fits = (p: Part) => (p.count / total) * usable >= String(p.count).length * CHAR_PX + PAD_PX
  const hovered = visible.find((p) => p.key === active)

  return (
    <div>
      <div ref={ref} className="relative">
        <div
          role="img"
          aria-label={visible.map((p) => `${p.meta.label}: ${p.count}`).join(', ')}
          className="flex h-7 w-full"
          style={{ gap: GAP }}
        >
          {visible.map((p) => (
            <div
              key={p.key}
              tabIndex={0}
              aria-label={`${p.meta.label}: ${p.count} ${unit} (${pct(p.count, total)})`}
              onPointerEnter={() => setActive(p.key)}
              onPointerLeave={() => setActive(null)}
              onFocus={() => setActive(p.key)}
              onBlur={() => setActive(null)}
              className={`flex min-w-0 items-center rounded px-2 text-xs font-semibold outline-offset-1 transition-opacity ${TONE_BG[p.meta.tone]} ${p.meta.onFill} ${
                active && active !== p.key ? 'opacity-60' : ''
              }`}
              style={{ flexGrow: p.count, flexBasis: 0 }}
            >
              {width > 0 && fits(p) ? p.count : null}
            </div>
          ))}
        </div>
        {hovered && (
          <div
            role="tooltip"
            className="pointer-events-none absolute top-9 left-0 z-10 rounded-lg border border-line bg-surface px-3 py-2 text-xs shadow-lg"
          >
            <div className="text-sm font-semibold text-ink">
              {hovered.count} <span className="font-normal text-ink-2">{unit}</span>
            </div>
            <div className="text-ink-2">
              {hovered.meta.label} · {pct(hovered.count, total)}
            </div>
            {hovered.title && <div className="mt-1 max-w-56 text-muted">{hovered.title}</div>}
          </div>
        )}
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-ink-2">
        {parts.map((p) => (
          <li key={p.key} className="flex items-center gap-1.5" title={p.title}>
            <span aria-hidden className={`h-2.5 w-2.5 rounded-sm ${TONE_BG[p.meta.tone]}`} />
            {p.meta.label}
            {(p.count === 0 || !fits(p)) && <span className="tabular-nums text-muted">{p.count}</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}

function pct(n: number, total: number): string {
  return `${Math.round((n / total) * 100)}%`
}
