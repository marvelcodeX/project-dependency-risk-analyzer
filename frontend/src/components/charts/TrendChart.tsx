import { useState } from 'react'
import { useWidth } from '../../hooks/useWidth'

export interface TrendPoint {
  id: number
  date: Date
  value: number // 0–100 composite risk
  level: string
  findings: number
  vulnerable: number
  total: number
}

const H = 160 // plot height
const AXIS_H = 22 // x-axis band (included in the SVG height)
const PAD = { left: 30, right: 36, top: 10 }
const Y_TICKS = [0, 25, 50, 75, 100]

/**
 * Single-series line: project risk score over successive scans of one
 * manifest. Crosshair snaps to the nearest scan; arrow keys step through
 * points; Enter opens the focused scan.
 */
export function TrendChart({
  points,
  activeId,
  onSelect,
}: {
  points: TrendPoint[]
  activeId: number | null
  onSelect: (id: number) => void
}) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const [hover, setHover] = useState<number | null>(null)

  const plotW = Math.max(0, width - PAD.left - PAD.right)
  const t0 = points[0]?.date.getTime() ?? 0
  const t1 = points[points.length - 1]?.date.getTime() ?? 0
  const x = (d: Date) =>
    PAD.left + (t1 === t0 ? plotW / 2 : ((d.getTime() - t0) / (t1 - t0)) * plotW)
  const y = (v: number) => PAD.top + H - (v / 100) * H

  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(p.date)},${y(p.value)}`).join(' ')
  const area =
    points.length > 1
      ? `${line} L${x(points[points.length - 1].date)},${y(0)} L${x(points[0].date)},${y(0)} Z`
      : ''

  function nearest(clientX: number, rect: DOMRect): number {
    const px = clientX - rect.left
    let best = 0
    for (let i = 1; i < points.length; i++) {
      if (Math.abs(x(points[i].date) - px) < Math.abs(x(points[best].date) - px)) best = i
    }
    return best
  }

  // Scans within one day: label times, otherwise dates.
  const sameDay = t1 - t0 < 24 * 3600 * 1000
  const tick = (d: Date) => (sameDay ? shortTime(d) : shortDate(d))
  const shown = hover ?? null
  const hp = shown !== null ? points[shown] : null
  const last = points[points.length - 1]

  return (
    <div ref={ref} className="relative">
      {width > 0 && (
        <svg
          width={width}
          height={PAD.top + H + AXIS_H}
          role="img"
          aria-label={`Risk score over ${points.length} scans, latest ${last?.value ?? 0}`}
          tabIndex={0}
          className="block touch-none"
          onPointerMove={(e) => setHover(nearest(e.clientX, e.currentTarget.getBoundingClientRect()))}
          onPointerLeave={() => setHover(null)}
          onClick={() => hp && onSelect(hp.id)}
          onKeyDown={(e) => {
            if (!points.length) return
            const cur = hover ?? points.length - 1
            if (e.key === 'ArrowLeft') setHover(Math.max(0, cur - 1))
            else if (e.key === 'ArrowRight') setHover(Math.min(points.length - 1, cur + 1))
            else if (e.key === 'Enter' && hp) onSelect(hp.id)
            else return
            e.preventDefault()
          }}
          onBlur={() => setHover(null)}
        >
          {/* gridlines + y ticks: solid hairlines, recessive */}
          {Y_TICKS.map((t) => (
            <g key={t}>
              <line x1={PAD.left} x2={PAD.left + plotW} y1={y(t)} y2={y(t)}
                stroke={t === 0 ? 'var(--baseline)' : 'var(--grid)'} strokeWidth={1} />
              <text x={PAD.left - 6} y={y(t)} dy="0.32em" textAnchor="end"
                className="fill-muted text-[10px] tabular-nums">{t}</text>
            </g>
          ))}
          {/* x labels: first and last date only */}
          {points.length > 0 && (
            <>
              <text x={x(points[0].date)} y={PAD.top + H + 15}
                textAnchor={points.length > 1 ? 'start' : 'middle'}
                className="fill-muted text-[10px]">{tick(points[0].date)}</text>
              {points.length > 1 && (
                <text x={x(last.date)} y={PAD.top + H + 15} textAnchor="end"
                  className="fill-muted text-[10px]">{tick(last.date)}</text>
              )}
            </>
          )}
          {area && <path d={area} fill="var(--series-1)" opacity={0.1} />}
          {points.length > 1 && (
            <path d={line} fill="none" stroke="var(--series-1)" strokeWidth={2}
              strokeLinejoin="round" strokeLinecap="round" />
          )}
          {/* crosshair */}
          {hp && (
            <line x1={x(hp.date)} x2={x(hp.date)} y1={PAD.top} y2={PAD.top + H}
              stroke="var(--baseline)" strokeWidth={1} />
          )}
          {/* markers: the active scan, the hovered one, and the latest */}
          {points.map((p, i) =>
            i === shown || p.id === activeId || i === points.length - 1 ? (
              <circle key={p.id} cx={x(p.date)} cy={y(p.value)} r={4.5}
                fill="var(--series-1)" stroke="var(--surface)" strokeWidth={2} />
            ) : null,
          )}
          {/* direct label: latest value at the line's end */}
          {last && (
            <text x={x(last.date) + 8} y={y(last.value)} dy="0.32em"
              className="fill-ink text-xs font-semibold">{last.value}</text>
          )}
        </svg>
      )}
      {hp && (
        <div
          role="tooltip"
          className="pointer-events-none absolute z-10 rounded-lg border border-line bg-surface px-3 py-2 text-xs shadow-lg"
          style={{
            left: Math.min(Math.max(0, x(hp.date) - 80), Math.max(0, width - 170)),
            top: 0,
          }}
        >
          <div className="text-sm font-semibold text-ink">
            {hp.value} <span className="font-normal text-ink-2">risk · {hp.level}</span>
          </div>
          <div className="text-ink-2">
            {hp.findings} findings · {hp.vulnerable}/{hp.total} vulnerable
          </div>
          <div className="text-muted">{hp.date.toLocaleString()}</div>
        </div>
      )}
    </div>
  )
}

function shortTime(d: Date): string {
  return d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })
}

function shortDate(d: Date): string {
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}
