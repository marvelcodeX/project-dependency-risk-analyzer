import { useEffect, useState } from 'react'
import type { AiExplanation, Dependency, Priority, Vulnerability } from '../api'
import { explainVuln, toExplainRequest } from '../api'

const PRIORITY_STYLES: Record<Priority, string> = {
  FIX_NOW: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
  FIX_THIS_WEEK: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  FIX_WHEN_CONVENIENT: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  MONITOR: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
}

const PRIORITY_LABEL: Record<Priority, string> = {
  FIX_NOW: 'Fix now',
  FIX_THIS_WEEK: 'Fix this week',
  FIX_WHEN_CONVENIENT: 'Fix when convenient',
  MONITOR: 'Monitor',
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
      <div className="flex items-center gap-2 px-4 py-4 text-sm text-gray-400">
        <span className="h-3 w-3 animate-spin rounded-full border-2 border-violet-500 border-t-transparent" />
        Generating explanation with the local LLM… (first run can take a while)
      </div>
    )
  }

  if (error) {
    return (
      <div className="px-4 py-4 text-sm text-rose-300">
        Couldn't generate an explanation: {error}
      </div>
    )
  }

  if (!exp) return null

  return (
    <div className="space-y-4 px-4 py-4 text-sm">
      <div className="flex items-center gap-2">
        <span
          className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ring-1 ring-inset ${
            PRIORITY_STYLES[exp.priority]
          }`}
        >
          {PRIORITY_LABEL[exp.priority]}
        </span>
        <span className="text-xs text-gray-500">
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
      <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">
        {title}
      </h4>
      <p
        className={`whitespace-pre-line text-gray-300 ${
          mono ? 'font-mono text-xs leading-relaxed' : ''
        }`}
      >
        {body}
      </p>
    </div>
  )
}
