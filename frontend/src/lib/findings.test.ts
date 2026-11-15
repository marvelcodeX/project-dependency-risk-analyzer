import { describe, expect, it } from 'vitest'
import {
  NO_FILTERS,
  SEVERITIES,
  activeFilterCount,
  countBy,
  filterFindings,
  flattenFindings,
  scanStats,
  sortFindings,
} from './findings'
import { normalizeSeverity } from '../severity'
import { dep, scan, vuln } from './fixtures'

const s = scan([
  [dep('express', { direct: true, ecosystem: 'npm' }), [
    vuln('GHSA-a', { risk_score: 80, severity: 'CRITICAL', cvss_score: 9.8, reachability: 'REACHABLE', in_cisa_kev: true }),
  ]],
  [dep('qs', { direct: false }), [
    vuln('GHSA-b', { risk_score: 40, severity: 'MODERATE', cvss_score: 5.3, fixed_version: null, cwe_ids: ['CWE-1321'] }),
    vuln('GHSA-c', { risk_score: 40, severity: 'LOW', cvss_score: null, has_public_exploit: true }),
  ]],
  [dep('lodash', { direct: true }), []],
])

describe('flattenFindings', () => {
  it('produces one row per (package, advisory), highest risk first', () => {
    const rows = flattenFindings(s)
    expect(rows.map((r) => r.vuln.id)).toEqual(['GHSA-a', 'GHSA-b', 'GHSA-c'])
    expect(new Set(rows.map((r) => r.key)).size).toBe(3)
  })
  it('keys rows by version so a package at two versions never collides', () => {
    const two = scan([
      [dep('lodash', { version: '3.10.1' }), [vuln('GHSA-x')]],
      [dep('lodash', { version: '4.17.20' }), [vuln('GHSA-x')]],
    ])
    expect(new Set(flattenFindings(two).map((r) => r.key)).size).toBe(2)
  })
})

describe('filterFindings', () => {
  const rows = flattenFindings(s)
  const ids = (f: Partial<typeof NO_FILTERS>) =>
    filterFindings(rows, { ...NO_FILTERS, ...f }).map((r) => r.vuln.id)

  it('passes everything with no filters', () => {
    expect(ids({})).toHaveLength(3)
  })
  it('matches severity after normalization (MODERATE → MEDIUM)', () => {
    expect(ids({ severities: new Set(['MEDIUM']) })).toEqual(['GHSA-b'])
  })
  it('filters by reachability, fix availability and exploitation', () => {
    expect(ids({ reachability: new Set(['REACHABLE']) })).toEqual(['GHSA-a'])
    expect(ids({ fix: 'none' })).toEqual(['GHSA-b'])
    expect(ids({ fix: 'available' })).toEqual(['GHSA-a', 'GHSA-c'])
    expect(ids({ exploitedOnly: true })).toEqual(['GHSA-a', 'GHSA-c'])
  })
  it('searches package, advisory id, summary, aliases and CWE', () => {
    expect(ids({ query: 'QS' })).toEqual(['GHSA-b', 'GHSA-c'])
    expect(ids({ query: 'cwe-1321' })).toEqual(['GHSA-b'])
    expect(ids({ query: '  ' })).toHaveLength(3)
  })
  it('counts active filters', () => {
    expect(activeFilterCount(NO_FILTERS)).toBe(0)
    expect(activeFilterCount({ ...NO_FILTERS, query: 'x', severities: new Set(['LOW', 'HIGH']), fix: 'none' })).toBe(4)
  })
})

describe('sortFindings', () => {
  const rows = flattenFindings(s)
  it('sorts by cvss with unknown scores last when descending', () => {
    expect(sortFindings(rows, 'cvss', 'desc').map((r) => r.vuln.id)).toEqual(['GHSA-a', 'GHSA-b', 'GHSA-c'])
  })
  it('sorts by severity rank, not alphabetically', () => {
    expect(sortFindings(rows, 'severity', 'asc').map((r) => normalizeSeverity(r.vuln.severity))).toEqual(['LOW', 'MEDIUM', 'CRITICAL'])
  })
  it('is stable and deterministic on ties', () => {
    const a = sortFindings(rows, 'package', 'asc').map((r) => r.key)
    expect(sortFindings([...rows].reverse(), 'package', 'asc').map((r) => r.key)).toEqual(a)
  })
})

describe('overview counts', () => {
  const rows = flattenFindings(s)
  it('counts by severity in fixed order, including zeros', () => {
    const c = countBy(rows, SEVERITIES, (f) => normalizeSeverity(f.vuln.severity))
    expect(c).toEqual([
      { key: 'CRITICAL', count: 1 },
      { key: 'HIGH', count: 0 },
      { key: 'MEDIUM', count: 1 },
      { key: 'LOW', count: 1 },
      { key: 'UNKNOWN', count: 0 },
    ])
  })
  it('summarizes the scan', () => {
    expect(scanStats(s, rows)).toEqual({
      dependencies: 3, direct: 2, transitive: 1, vulnerableDependencies: 2,
      findings: 3, reachable: 1, fixAvailable: 2, exploited: 2,
    })
  })
  it('reports unknown directness as null, not zero', () => {
    const py = scan([[dep('flask', { ecosystem: 'PyPI' }), []]])
    expect(scanStats(py, []).direct).toBeNull()
  })
})
