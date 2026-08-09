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

// Tailwind classes for each severity badge.
const STYLES: Record<string, string> = {
  CRITICAL: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
  HIGH: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  LOW: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
  UNKNOWN: 'bg-slate-500/15 text-slate-300 ring-slate-500/30',
}

export function severityClasses(s: Severity): string {
  return STYLES[normalizeSeverity(s)] ?? STYLES.UNKNOWN
}

// Risk-level styling (composite risk score buckets). Text color for numbers.
const RISK_TEXT: Record<string, string> = {
  CRITICAL: 'text-rose-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-amber-400',
  LOW: 'text-sky-400',
  NONE: 'text-emerald-400',
}

export function riskTextClass(level: string): string {
  return RISK_TEXT[level?.toUpperCase()] ?? 'text-gray-300'
}

// Reachability badge styling + short labels.
const REACH: Record<string, { cls: string; label: string; title: string }> = {
  REACHABLE: {
    cls: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
    label: 'reachable',
    title: 'Your code imports this package',
  },
  POTENTIALLY_REACHABLE: {
    cls: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
    label: 'maybe',
    title: 'Source analyzed but the import could not be confirmed',
  },
  UNREACHABLE: {
    cls: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30',
    label: 'unreachable',
    title: 'Not imported anywhere in the analyzed source',
  },
  UNKNOWN: {
    cls: 'bg-slate-500/10 text-slate-400 ring-slate-500/30',
    label: 'unknown',
    title: 'No project source was provided for reachability analysis',
  },
}

export function reachabilityMeta(r: string) {
  return REACH[r?.toUpperCase()] ?? REACH.UNKNOWN
}
