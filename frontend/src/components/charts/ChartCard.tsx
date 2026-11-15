import { useState, type ReactNode } from 'react'

/**
 * A chart's container: title, optional caption, and the table-view toggle —
 * every chart has a table twin so no value is reachable only by hover/color.
 */
export function ChartCard({
  title,
  caption,
  table,
  children,
}: {
  title: string
  caption?: ReactNode
  table: ReactNode
  children: ReactNode
}) {
  const [asTable, setAsTable] = useState(false)
  return (
    <figure className="m-0 rounded-xl border border-line bg-surface p-4">
      <div className="mb-3 flex items-start justify-between gap-3">
        <figcaption>
          <div className="text-sm font-semibold text-ink">{title}</div>
          {caption && <div className="mt-0.5 text-xs text-muted">{caption}</div>}
        </figcaption>
        <button
          onClick={() => setAsTable((t) => !t)}
          aria-pressed={asTable}
          className="shrink-0 rounded-md border border-line px-2 py-0.5 text-xs text-ink-2 transition hover:bg-surface-2"
        >
          {asTable ? 'Chart' : 'Table'}
        </button>
      </div>
      {asTable ? table : children}
    </figure>
  )
}

export function DataTable({
  head,
  rows,
}: {
  head: string[]
  rows: (string | number)[][]
}) {
  return (
    <table className="w-full text-left text-sm">
      <thead>
        <tr className="border-b border-line text-xs text-muted">
          {head.map((h, i) => (
            <th key={h} className={`py-1.5 font-medium ${i > 0 ? 'text-right' : ''}`}>
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={String(r[0])} className="border-b border-line last:border-0">
            {r.map((c, i) => (
              <td key={i} className={`py-1.5 text-ink ${i > 0 ? 'text-right tabular-nums' : ''}`}>
                {c}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}
