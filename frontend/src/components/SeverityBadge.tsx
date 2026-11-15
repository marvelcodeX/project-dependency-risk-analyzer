import type { Severity } from '../api'
import type { LevelMeta } from '../severity'
import { TONE_BG, reachabilityMeta, riskMeta, severityMeta } from '../severity'

/** A status pill: colored dot (identity) + text label in ink (meaning). */
export function StatusBadge({ meta, title }: { meta: LevelMeta; title?: string }) {
  return (
    <span
      title={title}
      className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface-2 px-2 py-0.5 text-xs font-medium whitespace-nowrap text-ink"
    >
      <span aria-hidden className={`h-2 w-2 shrink-0 rounded-full ${TONE_BG[meta.tone]}`} />
      {meta.label}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <StatusBadge meta={severityMeta(severity)} />
}

export function RiskBadge({ level }: { level: string }) {
  return <StatusBadge meta={riskMeta(level)} title={`Composite risk: ${level}`} />
}

export function ReachBadge({ reachability }: { reachability: string }) {
  const m = reachabilityMeta(reachability)
  return <StatusBadge meta={m} title={m.title} />
}

/** Small uppercase flag for exploitation signals (KEV / public exploit). */
export function Flag({ children, title }: { children: string; title: string }) {
  return (
    <span
      title={title}
      className="inline-flex items-center gap-1 rounded border border-critical/50 px-1.5 py-px text-[10px] font-semibold tracking-wide text-ink uppercase"
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-critical" />
      {children}
    </span>
  )
}
