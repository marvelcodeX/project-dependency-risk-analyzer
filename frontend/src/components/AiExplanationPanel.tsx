import { useEffect, useState } from 'react'
import type { AiExplanation, Dependency, Priority, Vulnerability } from '../api'
import { explainVuln, toExplainRequest } from '../api'
import type { LevelMeta } from '../severity'
import { StatusBadge } from './SeverityBadge'

// The model's priority, on the same status scale as severity.
const PRIORITY: Record<Priority, LevelMeta> = {
  FIX_NOW: { tone: 'critical', label: 'Fix now', onFill: 'text-white' },
  FIX_THIS_WEEK: { tone: 'serious', label: 'Fix this week', onFill: 'text-white' },
  FIX_WHEN_CONVENIENT: { tone: 'warning', label: 'Fix when convenient', onFill: 'text-[#0b0b0b]' },
  MONITOR: { tone: 'low', label: 'Monitor', onFill: 'text-[#0b0b0b]' },
}

interface Props {
  vuln: Vulnerability
  dep: Dependency
}

export function AiExplanationPanel({ vuln, dep }: Props) {
  const [exp, setExp] = useState<AiExplanation | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    setLoading(true)
    setError(null)
    explainVuln(toExplainRequest(vuln, dep))
      .then((r) => active && setExp(r))
      .catch((e) => active && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [vuln, dep])

  if (loading) {
    return (
      <div role="status" className="flex items-center gap-2 px-4 py-4 text-sm text-ink-2">
        <span aria-hidden className="h-3 w-3 animate-spin rounded-full border-2 border-accent border-t-transparent" />
        Generating explanation with the local LLM… (first run can take a while)
      </div>
    )
  }

  if (error) {
    return (
      <div role="alert" className="px-4 py-4 text-sm text-ink">
        <span className="font-semibold">Couldn't generate an explanation.</span>{' '}
        <span className="text-ink-2">{error}</span>
      </div>
    )
  }

  if (!exp) return null

  return (
    <div className="space-y-4 px-4 py-4 text-sm">
      <div className="flex items-center gap-2">
        <StatusBadge meta={PRIORITY[exp.priority]} title="Priority suggested by the local LLM" />
        <span className="text-xs text-muted">
          {exp.cached ? 'cached' : 'generated'} · {exp.model}
        </span>
      </div>

      <Section title="What's the issue?" body={exp.summary} />
      <Section title="How could this be exploited?" body={exp.attack_scenario} />
      <Section title="Impact on your project" body={exp.project_impact} />
      <Section title="How to fix it" body={exp.fix_steps} mono />
    </div>
  )
}

function Section({
  title,
  body,
  mono = false,
}: {
  title: string
  body: string
  mono?: boolean
}) {
  if (!body) return null
  return (
    <div>
      <h4 className="mb-1 text-xs font-semibold tracking-wide text-ink-2 uppercase">
        {title}
      </h4>
      <p
        className={`whitespace-pre-line text-ink ${
          mono ? 'font-mono text-xs leading-relaxed' : ''
        }`}
      >
        {body}
      </p>
    </div>
  )
}
