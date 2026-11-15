import type { ScanResponse } from '../api'
import type { Finding } from '../lib/findings'
import { REACHABILITIES, SEVERITIES, countBy, scanStats } from '../lib/findings'
import { normalizeSeverity, reachabilityMeta, riskMeta, severityMeta } from '../severity'
import { ChartCard, DataTable } from './charts/ChartCard'
import { Meter } from './charts/Meter'
import { SegmentedBar } from './charts/SegmentedBar'
import { Flag, RiskBadge, SeverityBadge } from './SeverityBadge'

export function Overview({
  scan,
  findings,
  onOpenFinding,
}: {
  scan: ScanResponse
  findings: Finding[]
  onOpenFinding: (key: string) => void
}) {
  const stats = scanStats(scan, findings)
  const risk = riskMeta(scan.risk_level)
  const bySeverity = countBy(findings, SEVERITIES, (f) => normalizeSeverity(f.vuln.severity))
  const byReach = countBy(findings, REACHABILITIES, (f) => f.vuln.reachability)
  const top = findings.slice(0, 5)

  return (
    <div className="space-y-4">
      {/* Hero: the one number this view leads with */}
      <section className="rounded-xl border border-line bg-surface p-5">
        <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
          <div>
            <div className="text-xs font-medium text-ink-2">Project risk score</div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-5xl font-semibold leading-none text-ink">{scan.risk_score}</span>
              <span className="text-sm text-muted">/ 100</span>
            </div>
          </div>
          <div className="mb-1">
            <RiskBadge level={scan.risk_level} />
          </div>
          <p className="mb-1 w-full max-w-md text-xs text-ink-2 sm:w-auto sm:flex-1">
            The highest composite score among this scan's findings: CVSS, exploitation in the
            wild, reachability, fix availability and dependency depth.
          </p>
        </div>
        <div className="mt-4">
          <Meter value={scan.risk_score} max={100} meta={risk} label={`Risk ${scan.risk_score} of 100`} />
        </div>
      </section>

      {/* KPI row */}
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <Stat
          label="Dependencies"
          value={stats.dependencies}
          note={stats.direct !== null ? `${stats.direct} direct · ${stats.transitive} transitive` : undefined}
        />
        <Stat label="Vulnerable packages" value={stats.vulnerableDependencies} />
        <Stat label="Findings" value={stats.findings} />
        <Stat label="Reachable findings" value={stats.reachable} note="imported by your code" />
        <Stat label="Fix available" value={stats.fixAvailable} note={stats.findings ? `of ${stats.findings}` : undefined} />
        <Stat label="Exploited / public exploit" value={stats.exploited} note="CISA KEV or PoC" />
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <ChartCard
          title="Findings by severity"
          caption="Advisory severity (CVSS), before project context"
          table={<DataTable head={['Severity', 'Findings']} rows={bySeverity.map((s) => [severityMeta(s.key).label, s.count])} />}
        >
          <SegmentedBar unit="findings" parts={bySeverity.map((s) => ({ key: s.key, meta: severityMeta(s.key), count: s.count }))} />
        </ChartCard>
        <ChartCard
          title="Findings by reachability"
          caption="Does your code actually use the vulnerable package?"
          table={<DataTable head={['Reachability', 'Findings']} rows={byReach.map((r) => [reachabilityMeta(r.key).label, r.count])} />}
        >
          <SegmentedBar
            unit="findings"
            parts={byReach.map((r) => ({ key: r.key, meta: reachabilityMeta(r.key), count: r.count, title: reachabilityMeta(r.key).title }))}
          />
        </ChartCard>
      </section>

      <section className="rounded-xl border border-line bg-surface">
        <h2 className="border-b border-line px-4 py-3 text-sm font-semibold text-ink">
          Most urgent findings
        </h2>
        {top.length === 0 ? (
          <p className="px-4 py-6 text-sm text-ink-2">
            <span className="font-medium text-good-ink">No known vulnerabilities</span> in{' '}
            {scan.total_dependencies} dependencies.
          </p>
        ) : (
          <ol className="divide-y divide-line">
            {top.map((f) => (
              <li key={f.key}>
                <button
                  onClick={() => onOpenFinding(f.key)}
                  className="flex w-full items-center gap-4 px-4 py-3 text-left transition hover:bg-surface-2"
                >
                  <span className="w-8 shrink-0 text-right text-lg font-semibold tabular-nums text-ink">
                    {f.vuln.risk_score}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-sm text-ink">
                      {f.dep.name} <span className="text-muted">{f.dep.version}</span>
                    </span>
                    <span className="block truncate text-xs text-ink-2">{f.vuln.summary}</span>
                  </span>
                  <span className="hidden shrink-0 items-center gap-2 sm:flex">
                    {f.vuln.in_cisa_kev && <Flag title="CISA Known Exploited Vulnerability">KEV</Flag>}
                    <SeverityBadge severity={f.vuln.severity} />
                  </span>
                </button>
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  )
}

function Stat({ label, value, note }: { label: string; value: number; note?: string }) {
  return (
    <div className="rounded-xl border border-line bg-surface px-4 py-3">
      <div className="text-xs font-medium text-ink-2">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-ink">{value.toLocaleString()}</div>
      {note && <div className="mt-0.5 text-xs text-muted">{note}</div>}
    </div>
  )
}
