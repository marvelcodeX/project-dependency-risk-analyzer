// Pure helpers for the dashboard: flatten, filter, sort and count findings.
// Kept free of React so they can be unit-tested (findings.test.ts).

import type { Dependency, Reachability, ScanResponse, Vulnerability } from '../api'
import { normalizeSeverity } from '../severity'

export interface Finding {
  /** Unique per row: a lockfile can hold one package at several versions. */
  key: string
  dep: Dependency
  vuln: Vulnerability
}

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const
export const REACHABILITIES: Reachability[] = [
  'REACHABLE',
  'POTENTIALLY_REACHABLE',
  'UNREACHABLE',
  'UNKNOWN',
]

export function depKey(dep: Dependency): string {
  return `${dep.name}@${dep.version ?? ''}`
}

export function flattenFindings(scan: ScanResponse): Finding[] {
  const out: Finding[] = []
  for (const r of scan.results) {
    for (const v of r.vulnerabilities) {
      out.push({ key: `${depKey(r.dependency)}|${v.id}`, dep: r.dependency, vuln: v })
    }
  }
  return sortFindings(out, 'risk', 'desc')
}

// ---- filtering -------------------------------------------------------------

export interface Filters {
  query: string
  severities: Set<string> // empty = all
  reachability: Set<string> // empty = all
  ecosystems: Set<string> // empty = all
  fix: 'any' | 'available' | 'none'
  exploitedOnly: boolean // KEV or public exploit
}

export const NO_FILTERS: Filters = {
  query: '',
  severities: new Set(),
  reachability: new Set(),
  ecosystems: new Set(),
  fix: 'any',
  exploitedOnly: false,
}

export function isExploited(v: Vulnerability): boolean {
  return v.in_cisa_kev || v.has_public_exploit
}

export function filterFindings(rows: Finding[], f: Filters): Finding[] {
  const q = f.query.trim().toLowerCase()
  return rows.filter(({ dep, vuln }) => {
    if (f.severities.size && !f.severities.has(normalizeSeverity(vuln.severity))) return false
    if (f.reachability.size && !f.reachability.has(vuln.reachability)) return false
    if (f.ecosystems.size && !f.ecosystems.has(dep.ecosystem)) return false
    if (f.fix === 'available' && !vuln.fixed_version) return false
    if (f.fix === 'none' && vuln.fixed_version) return false
    if (f.exploitedOnly && !isExploited(vuln)) return false
    if (q) {
      const haystack = [dep.name, vuln.id, vuln.summary, ...vuln.aliases, ...vuln.cwe_ids]
        .join(' ')
        .toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  })
}

export function activeFilterCount(f: Filters): number {
  return (
    (f.query.trim() ? 1 : 0) +
    f.severities.size +
    f.reachability.size +
    f.ecosystems.size +
    (f.fix !== 'any' ? 1 : 0) +
    (f.exploitedOnly ? 1 : 0)
  )
}

// ---- sorting ---------------------------------------------------------------

export type SortKey = 'risk' | 'cvss' | 'severity' | 'package' | 'advisory'

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
}

function compare(a: Finding, b: Finding, key: SortKey): number {
  switch (key) {
    case 'risk':
      return a.vuln.risk_score - b.vuln.risk_score
    case 'cvss':
      return (a.vuln.cvss_score ?? -1) - (b.vuln.cvss_score ?? -1)
    case 'severity':
      return (
        SEVERITY_RANK[normalizeSeverity(a.vuln.severity)] -
        SEVERITY_RANK[normalizeSeverity(b.vuln.severity)]
      )
    case 'package':
      return a.dep.name.localeCompare(b.dep.name)
    case 'advisory':
      return a.vuln.id.localeCompare(b.vuln.id)
  }
}

/** Stable sort; ties fall back to risk (desc) then package name. */
export function sortFindings(rows: Finding[], key: SortKey, dir: 'asc' | 'desc'): Finding[] {
  const sign = dir === 'asc' ? 1 : -1
  return [...rows].sort(
    (a, b) =>
      sign * compare(a, b, key) ||
      b.vuln.risk_score - a.vuln.risk_score ||
      a.dep.name.localeCompare(b.dep.name) ||
      a.vuln.id.localeCompare(b.vuln.id),
  )
}

// ---- counts for the overview ---------------------------------------------

export function countBy<T extends string>(
  rows: Finding[],
  keys: readonly T[],
  pick: (f: Finding) => string,
): { key: T; count: number }[] {
  const counts = new Map<string, number>()
  for (const r of rows) counts.set(pick(r), (counts.get(pick(r)) ?? 0) + 1)
  return keys.map((key) => ({ key, count: counts.get(key) ?? 0 }))
}

export interface ScanStats {
  dependencies: number
  direct: number | null // null when the manifest doesn't record it
  transitive: number | null
  vulnerableDependencies: number
  findings: number
  reachable: number
  fixAvailable: number
  exploited: number
}

export function scanStats(scan: ScanResponse, rows: Finding[]): ScanStats {
  const deps = scan.results.map((r) => r.dependency)
  const known = deps.some((d) => d.direct !== null)
  return {
    dependencies: scan.total_dependencies,
    direct: known ? deps.filter((d) => d.direct === true).length : null,
    transitive: known ? deps.filter((d) => d.direct === false).length : null,
    vulnerableDependencies: scan.vulnerable_dependencies,
    findings: rows.length,
    reachable: rows.filter((r) => r.vuln.reachability === 'REACHABLE').length,
    fixAvailable: rows.filter((r) => r.vuln.fixed_version).length,
    exploited: rows.filter((r) => isExploited(r.vuln)).length,
  }
}
