// Test fixtures shared by the lib/*.test.ts files.
import type { Dependency, ScanResponse, Vulnerability } from '../api'

export function dep(name: string, over: Partial<Dependency> = {}): Dependency {
  return {
    name,
    version: '1.0.0',
    ecosystem: 'npm',
    pinned: true,
    raw_spec: '1.0.0',
    direct: null,
    depth: null,
    depends_on: [],
    version_source: 'declared',
    ...over,
  }
}

export function vuln(id: string, over: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id,
    summary: `${id} summary`,
    details: '',
    aliases: [],
    severity: 'HIGH',
    cvss_score: 7.5,
    cvss_vector: null,
    fixed_version: '2.0.0',
    references: [],
    in_cisa_kev: false,
    risk_score: 50,
    risk_level: 'HIGH',
    reachability: 'UNKNOWN',
    cwe_ids: [],
    has_public_exploit: false,
    ...over,
  }
}

export function scan(results: [Dependency, Vulnerability[]][]): ScanResponse {
  return {
    id: 1,
    filename: 'package-lock.json',
    created_at: '2026-11-15T10:00:00Z',
    total_dependencies: results.length,
    vulnerable_dependencies: results.filter(([, v]) => v.length).length,
    risk_score: Math.max(0, ...results.flatMap(([, vs]) => vs.map((v) => v.risk_score))),
    risk_level: 'HIGH',
    results: results.map(([dependency, vulnerabilities]) => ({ dependency, vulnerabilities })),
  }
}
