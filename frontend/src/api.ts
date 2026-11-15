// Types mirror the backend Pydantic schemas in app/schemas/scan.py.

export interface Dependency {
  name: string
  version: string | null
  ecosystem: string
  pinned: boolean
  raw_spec: string
  /** null = unknown (the manifest doesn't say). */
  direct: boolean | null
  /** 0 = direct, 1+ = transitive hops; null = unknown. */
  depth: number | null
  /** Graph keys ("name@version") of this package's own dependencies. */
  depends_on: string[]
  /** "declared" = from the manifest; "latest" = resolved from the registry. */
  version_source: 'declared' | 'latest' | string
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
  cwe_ids: string[]
  has_public_exploit: boolean
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
  total_findings: number
}

export interface ManifestFormat {
  format: string
  ecosystem: string
  /** Whether source can be analyzed for reachability in this ecosystem. */
  reachability: boolean
}

/** Supported manifest formats, from the backend (single source of truth). */
export async function listFormats(): Promise<ManifestFormat[]> {
  const res = await fetch('/api/ecosystems')
  if (!res.ok) throw new Error(`Failed to load formats (${res.status})`)
  return res.json()
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
  if (!res.ok) throw new Error(await errorDetail(res, 'Scan failed'))
  return res.json()
}

/** Prefer FastAPI's `{"detail": ...}` message over a raw JSON body. */
async function errorDetail(res: Response, prefix: string): Promise<string> {
  const text = await res.text()
  try {
    const detail = JSON.parse(text).detail
    if (typeof detail === 'string') return `${prefix}: ${detail}`
  } catch {
    /* not JSON */
  }
  return `${prefix} (${res.status}): ${text}`
}

/** Fallback until /api/ecosystems answers (or if it can't be reached). */
export const FALLBACK_FORMATS: ManifestFormat[] = [
  { format: 'requirements.txt', ecosystem: 'PyPI', reachability: true },
  { format: 'package.json', ecosystem: 'npm', reachability: true },
  { format: 'package-lock.json', ecosystem: 'npm', reachability: true },
  { format: 'go.mod', ecosystem: 'Go', reachability: false },
  { format: 'pom.xml', ecosystem: 'Maven', reachability: false },
]

/** Scan an uploaded dependency file, optionally with source for reachability. */
export async function scanFile(
  file: File,
  sourceFiles: Record<string, string> = {},
): Promise<ScanResponse> {
  const form = new FormData()
  form.append('file', file)
  for (const [name, code] of Object.entries(sourceFiles)) {
    form.append('source_files', new Blob([code], { type: 'text/plain' }), name)
  }
  const res = await fetch('/api/scan/file', { method: 'POST', body: form })
  if (!res.ok) throw new Error(await errorDetail(res, 'Scan failed'))
  return res.json()
}

export type ReportFormat = 'json' | 'sarif' | 'cyclonedx' | 'markdown' | 'html'

/** URL of an exported report for a saved scan (served by the backend). */
export function reportUrl(
  id: number,
  format: ReportFormat,
  download = true,
): string {
  return `/api/scans/${id}/report?format=${format}&download=${download}`
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
    cwe_ids: vuln.cwe_ids,
    has_public_exploit: vuln.has_public_exploit,
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
