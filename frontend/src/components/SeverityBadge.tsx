import type { Severity } from '../api'
import { normalizeSeverity, severityClasses } from '../severity'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ring-1 ring-inset ${severityClasses(
        severity,
      )}`}
    >
      {normalizeSeverity(severity)}
    </span>
  )
}
