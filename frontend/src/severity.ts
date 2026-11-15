import type { Severity } from './api'

/** Normalize the varied severity labels the backend can emit into buckets. */
export function normalizeSeverity(s: Severity): string {
  const up = (s || 'UNKNOWN').toUpperCase()
  if (up === 'MODERATE') return 'MEDIUM'
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(up)) return up
  if (up === 'NONE') return 'LOW'
  return 'UNKNOWN'
}

// Rank for sorting — higher is more urgent.
const RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
}

export function severityRank(s: Severity): number {
  return RANK[normalizeSeverity(s)] ?? 0
}

/**
 * Status tone for a severity / risk level. Tones map to the fixed status
 * scale (index.css): mark color via `bg-${tone}`. Text never takes the tone
 * color — it stays in ink tokens, next to a colored mark.
 */
export type Tone = 'critical' | 'serious' | 'warning' | 'low' | 'good' | 'unknown'

export interface LevelMeta {
  tone: Tone
  label: string
  /** Text color for a label printed *inside* a filled mark of this tone. */
  onFill: 'text-white' | 'text-[#0b0b0b]'
}

const LEVELS: Record<string, LevelMeta> = {
  CRITICAL: { tone: 'critical', label: 'Critical', onFill: 'text-white' },
  HIGH: { tone: 'serious', label: 'High', onFill: 'text-white' },
  MEDIUM: { tone: 'warning', label: 'Medium', onFill: 'text-[#0b0b0b]' },
  LOW: { tone: 'low', label: 'Low', onFill: 'text-[#0b0b0b]' },
  NONE: { tone: 'good', label: 'None', onFill: 'text-white' },
  UNKNOWN: { tone: 'unknown', label: 'Unknown', onFill: 'text-[#0b0b0b]' },
}

export function severityMeta(s: Severity): LevelMeta {
  return LEVELS[normalizeSeverity(s)] ?? LEVELS.UNKNOWN
}

/** Composite risk levels (CRITICAL … NONE) share the same scale. */
export function riskMeta(level: string): LevelMeta {
  return LEVELS[level?.toUpperCase()] ?? LEVELS.UNKNOWN
}

// Background classes per tone, spelled out so Tailwind can see them.
export const TONE_BG: Record<Tone, string> = {
  critical: 'bg-critical',
  serious: 'bg-serious',
  warning: 'bg-warning',
  low: 'bg-low',
  good: 'bg-good',
  unknown: 'bg-unknown',
}

// Lighter step of each tone, for meter tracks.
export const TONE_TRACK: Record<Tone, string> = {
  critical: 'bg-critical/20',
  serious: 'bg-serious/20',
  warning: 'bg-warning/25',
  low: 'bg-low/25',
  good: 'bg-good/20',
  unknown: 'bg-unknown/25',
}

// Reachability states: concern-ordered, on the same status scale.
export interface ReachMeta extends LevelMeta {
  title: string
}

const REACH: Record<string, ReachMeta> = {
  REACHABLE: {
    tone: 'serious',
    label: 'Reachable',
    onFill: 'text-white',
    title: 'Your code imports this package',
  },
  POTENTIALLY_REACHABLE: {
    tone: 'warning',
    label: 'Potentially',
    onFill: 'text-[#0b0b0b]',
    title: 'Pulled in by a package your code imports, or the import could not be confirmed',
  },
  UNREACHABLE: {
    tone: 'good',
    label: 'Unreachable',
    onFill: 'text-white',
    title: 'Nothing your code imports leads to this package',
  },
  UNKNOWN: {
    tone: 'unknown',
    label: 'Unknown',
    onFill: 'text-[#0b0b0b]',
    title: 'No source in this language was provided for reachability analysis',
  },
}

export function reachabilityMeta(r: string): ReachMeta {
  return REACH[r?.toUpperCase()] ?? REACH.UNKNOWN
}
