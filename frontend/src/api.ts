// Types mirror the backend Pydantic schemas in app/schemas/scan.py.

export interface Dependency {
  name: string
  version: string | null
  ecosystem: string
  pinned: boolean
  raw_spec: string
}

export type Severity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'MODERATE'
  | 'LOW'
  | 'NONE'
  | 'UNKNOWN'
  | string

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'

export interface Vulnerability {
  id: string
  summary: string
  details: string
  aliases: string[]
  severity: Severity
  cvss_score: number | null
  cvss_vector: string | null
  fixed_version: string | null
  references: string[]
  in_cisa_kev: boolean
  risk_score: number
  risk_level: RiskLevel
  reachability: Reachability
}

export type Reachability =
  | 'UNKNOWN'
  | 'REACHABLE'
  | 'POTENTIALLY_REACHABLE'
  | 'UNREACHABLE'

export interface DependencyScanResult {
  dependency: Dependency
  vulnerabilities: Vulnerability[]
}

export interface ScanResponse {
  id: number | null
  filename: string
  created_at: string | null
  total_dependencies: number
  vulnerable_dependencies: number
  risk_score: number
  risk_level: RiskLevel
  results: DependencyScanResult[]
}

export interface ScanListItem {
  id: number
  filename: string
  created_at: string
  total_dependencies: number
  vulnerable_dependencies: number
  risk_score: number
  risk_level: RiskLevel
}

/** Scan pasted requirements.txt text, optionally with source for reachability. */
export async function scanText(
  content: string,
  filename = 'requirements.txt',
  sourceFiles: Record<string, string> = {},
): Promise<ScanResponse> {
  const res = await fetch('/api/scan/text', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, filename, source_files: sourceFiles }),
  })
  if (!res.ok) {
    throw new Error(`Scan failed (${res.status}): ${await res.text()}`)
  }
  return res.json()
}

/** Scan an uploaded dependency file. */
export async function scanFile(file: File): Promise<ScanResponse> {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch('/api/scan/file', { method: 'POST', body: form })
  if (!res.ok) {
    throw new Error(`Scan failed (${res.status}): ${await res.text()}`)
  }
  return res.json()
}

/** List previously saved scans, newest first. */
export async function listScans(): Promise<ScanListItem[]> {
  const res = await fetch('/api/scans')
  if (!res.ok) throw new Error(`Failed to load history (${res.status})`)
  return res.json()
}

/** Reload a saved scan by id. */
export async function getScan(id: number): Promise<ScanResponse> {
  const res = await fetch(`/api/scans/${id}`)
  if (!res.ok) throw new Error(`Failed to load scan ${id} (${res.status})`)
  return res.json()
}

// ---- AI explanation layer (local LLM via Ollama) --------------------------

export type Priority =
  | 'FIX_NOW'
  | 'FIX_THIS_WEEK'
  | 'FIX_WHEN_CONVENIENT'
  | 'MONITOR'

export interface AiExplanation {
  summary: string
  attack_scenario: string
  project_impact: string
  fix_steps: string
  priority: Priority
  model: string
  cached: boolean
}

export interface AiStatus {
  available: boolean
  model: string
  detail: string
}

/** Build the explain-request payload from a finding + its dependency. */
export function toExplainRequest(
  vuln: Vulnerability,
  dep: Dependency,
): Record<string, unknown> {
  return {
    vuln_id: vuln.id,
    cve_id: vuln.aliases.find((a) => a.startsWith('CVE-')) ?? null,
    package: dep.name,
    version: dep.version,
    ecosystem: dep.ecosystem,
    severity: vuln.severity,
    cvss_score: vuln.cvss_score,
    summary: vuln.summary,
    details: vuln.details,
    fixed_version: vuln.fixed_version,
    in_cisa_kev: vuln.in_cisa_kev,
    risk_level: vuln.risk_level,
    reachability: vuln.reachability,
  }
}

/** Check whether the local LLM is reachable. */
export async function aiStatus(): Promise<AiStatus> {
  const res = await fetch('/api/ai/status')
  if (!res.ok) throw new Error(`AI status failed (${res.status})`)
  return res.json()
}

/** Generate (or fetch cached) a plain-English explanation for a finding. */
export async function explainVuln(
  payload: Record<string, unknown>,
): Promise<AiExplanation> {
  const res = await fetch('/api/ai/explain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    let detail = `${res.status}`
    try {
      detail = (await res.json()).detail ?? detail
    } catch {
      /* ignore */
    }
    throw new Error(detail)
  }
  return res.json()
}
