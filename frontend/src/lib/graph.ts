// Dependency-graph helpers over a scan's `depends_on` edges.
// The graph is a DAG in practice, but npm can produce cycles, so every walk
// tracks what it has visited.

import type { Dependency, ScanResponse, Vulnerability } from '../api'
import { depKey } from './findings'

export interface GraphNode {
  key: string
  dep: Dependency
  vulns: Vulnerability[]
  children: string[] // keys present in this scan
}

export interface DepGraph {
  nodes: Map<string, GraphNode>
  roots: string[] // direct dependencies (or everything when unknown)
  /** True when the manifest records edges (npm lockfile). */
  hasEdges: boolean
  /** True when the manifest says which packages are direct. */
  knowsDirect: boolean
}

export function buildGraph(scan: ScanResponse): DepGraph {
  const nodes = new Map<string, GraphNode>()
  for (const r of scan.results) {
    nodes.set(depKey(r.dependency), {
      key: depKey(r.dependency),
      dep: r.dependency,
      vulns: r.vulnerabilities,
      children: [],
    })
  }
  for (const n of nodes.values()) {
    n.children = n.dep.depends_on.filter((k) => nodes.has(k) && k !== n.key).sort()
  }
  const all = [...nodes.values()]
  const knowsDirect = all.some((n) => n.dep.direct !== null)
  const hasEdges = all.some((n) => n.children.length > 0)
  let roots = knowsDirect
    ? all.filter((n) => n.dep.direct).map((n) => n.key)
    : hasEdges
      ? // v1 lockfiles: no directness, but packages nothing depends on are roots
        rootsByIndegree(all)
      : all.map((n) => n.key)
  if (roots.length === 0) roots = all.map((n) => n.key)
  roots.sort()
  return { nodes, roots, hasEdges, knowsDirect }
}

function rootsByIndegree(all: GraphNode[]): string[] {
  const pointedTo = new Set(all.flatMap((n) => n.children))
  return all.filter((n) => !pointedTo.has(n.key)).map((n) => n.key)
}

/**
 * Shortest chain from a direct dependency to `target`, inclusive — the answer
 * to "why is this package in my project?". Null when unreachable from roots.
 */
export function pathTo(graph: DepGraph, target: string): string[] | null {
  if (!graph.nodes.has(target)) return null
  if (graph.roots.includes(target)) return [target]
  const prev = new Map<string, string>()
  const seen = new Set(graph.roots)
  let frontier = [...graph.roots]
  while (frontier.length) {
    const next: string[] = []
    for (const k of frontier) {
      for (const c of graph.nodes.get(k)?.children ?? []) {
        if (seen.has(c)) continue
        seen.add(c)
        prev.set(c, k)
        if (c === target) {
          const path = [c]
          let cur = c
          while (prev.has(cur)) {
            cur = prev.get(cur)!
            path.unshift(cur)
          }
          return path
        }
        next.push(c)
      }
    }
    frontier = next
  }
  return null
}

/**
 * Keys whose subtree contains at least one vulnerable package (including the
 * vulnerable packages themselves). Used to show "only paths to vulnerabilities".
 */
export function keysLeadingToVulns(graph: DepGraph): Set<string> {
  // Walk *up* from every vulnerable package along reverse edges; correct even
  // when the graph has cycles.
  const parents = new Map<string, string[]>()
  for (const n of graph.nodes.values()) {
    for (const c of n.children) parents.set(c, [...(parents.get(c) ?? []), n.key])
  }
  const result = new Set<string>()
  const stack = [...graph.nodes.values()].filter((n) => n.vulns.length).map((n) => n.key)
  while (stack.length) {
    const k = stack.pop()!
    if (result.has(k)) continue
    result.add(k)
    stack.push(...(parents.get(k) ?? []))
  }
  return result
}

/** Count of distinct packages below `key` (its transitive closure). */
export function subtreeSize(graph: DepGraph, key: string): number {
  const seen = new Set<string>()
  const stack = [...(graph.nodes.get(key)?.children ?? [])]
  while (stack.length) {
    const k = stack.pop()!
    if (seen.has(k) || k === key) continue
    seen.add(k)
    stack.push(...(graph.nodes.get(k)?.children ?? []))
  }
  return seen.size
}
