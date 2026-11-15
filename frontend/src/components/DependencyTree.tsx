import { useMemo, useState } from 'react'
import type { Vulnerability } from '../api'
import type { DepGraph, GraphNode } from '../lib/graph'
import { keysLeadingToVulns, subtreeSize } from '../lib/graph'
import { TONE_BG, severityMeta, severityRank } from '../severity'

/**
 * Dependency tree from the lockfile graph. Defaults to only the paths that
 * lead to vulnerable packages, expanded — the "where does this come from?"
 * view. Cycles are cut where a package would repeat on its own path.
 */
export function DependencyTree({
  graph,
  onOpenFinding,
}: {
  graph: DepGraph
  onOpenFinding: (key: string) => void
}) {
  const leading = useMemo(() => keysLeadingToVulns(graph), [graph])
  const anyVulns = leading.size > 0
  const [onlyVulnPaths, setOnlyVulnPaths] = useState(anyVulns)
  const [query, setQuery] = useState('')
  const [toggled, setToggled] = useState<Map<string, boolean>>(new Map())

  const q = query.trim().toLowerCase()
  const visible = (key: string) => !onlyVulnPaths || leading.has(key)
  const roots = graph.roots.filter(visible).filter((k) => !q || matchesBelow(graph, k, q))

  // Path-scoped expansion: the same package can appear under several parents.
  const isOpen = (pathKey: string, nodeKey: string) =>
    toggled.get(pathKey) ?? ((onlyVulnPaths && leading.has(nodeKey)) || (!!q && matchesBelow(graph, nodeKey, q, true)))
  const toggle = (pathKey: string, nodeKey: string) =>
    setToggled((m) => new Map(m).set(pathKey, !isOpen(pathKey, nodeKey)))

  if (!graph.hasEdges) {
    return <FlatList graph={graph} onOpenFinding={onOpenFinding} />
  }

  return (
    <div className="rounded-xl border border-line bg-surface">
      <div className="flex flex-wrap items-center gap-3 border-b border-line p-3">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Find a package…"
          aria-label="Find a package in the tree"
          className="h-8 w-full rounded-lg border border-line bg-page px-3 text-sm text-ink outline-none placeholder:text-muted focus:border-accent sm:w-56"
        />
        <label className={`flex items-center gap-2 text-xs ${anyVulns ? 'text-ink-2' : 'text-muted'}`}>
          <input
            type="checkbox"
            checked={onlyVulnPaths}
            disabled={!anyVulns}
            onChange={(e) => {
              setOnlyVulnPaths(e.target.checked)
              setToggled(new Map())
            }}
            className="accent-[var(--accent)]"
          />
          Only paths to vulnerable packages
        </label>
        <span className="ml-auto text-xs text-muted">
          {graph.roots.length} direct · {graph.nodes.size} total
        </span>
      </div>
      {roots.length === 0 ? (
        <p className="px-4 py-8 text-center text-sm text-ink-2">
          {q ? 'No package matches.' : 'No vulnerable packages in this dependency tree.'}
        </p>
      ) : (
        <ul role="tree" aria-label="Dependency tree" className="max-h-[70vh] overflow-auto py-2 font-mono text-xs">
          {roots.map((k) => (
            <TreeRow
              key={k}
              graph={graph}
              nodeKey={k}
              pathKey={k}
              ancestors={new Set()}
              depth={0}
              visible={visible}
              isOpen={isOpen}
              toggle={toggle}
              query={q}
              onOpenFinding={onOpenFinding}
            />
          ))}
        </ul>
      )}
    </div>
  )
}

function TreeRow({
  graph,
  nodeKey,
  pathKey,
  ancestors,
  depth,
  visible,
  isOpen,
  toggle,
  query,
  onOpenFinding,
}: {
  graph: DepGraph
  nodeKey: string
  pathKey: string
  ancestors: Set<string>
  depth: number
  visible: (k: string) => boolean
  isOpen: (pathKey: string, nodeKey: string) => boolean
  toggle: (pathKey: string, nodeKey: string) => void
  query: string
  onOpenFinding: (key: string) => void
}) {
  const node = graph.nodes.get(nodeKey)!
  const cyclic = ancestors.has(nodeKey)
  const children = cyclic ? [] : node.children.filter(visible)
  const open = children.length > 0 && isOpen(pathKey, nodeKey)
  const nextAncestors = new Set(ancestors).add(nodeKey)
  const hit = !!query && nodeKey.toLowerCase().includes(query)

  return (
    <li role="treeitem" aria-expanded={children.length ? open : undefined} aria-level={depth + 1}>
      <div className="flex items-center gap-1.5 py-0.5 pr-3 hover:bg-surface-2" style={{ paddingLeft: 12 + depth * 18 }}>
        {children.length ? (
          <button
            onClick={() => toggle(pathKey, nodeKey)}
            aria-label={`${open ? 'Collapse' : 'Expand'} ${nodeKey}`}
            className="flex h-5 w-5 items-center justify-center rounded text-ink-2 hover:bg-surface hover:text-ink"
          >
            <span aria-hidden className={`inline-block transition-transform ${open ? 'rotate-90' : ''}`}>›</span>
          </button>
        ) : (
          <span className="w-5" aria-hidden />
        )}
        <span className={`${hit ? 'rounded bg-accent/15 px-1' : ''} ${node.vulns.length ? 'font-semibold text-ink' : 'text-ink-2'}`}>
          {node.dep.name}
          <span className="font-normal text-muted">@{node.dep.version}</span>
        </span>
        {node.vulns.length > 0 && <VulnMarker node={node} onOpen={onOpenFinding} />}
        {cyclic && <span className="text-muted">(cycle)</span>}
        {!open && !cyclic && node.children.length > 0 && (
          <span className="text-muted">
            {subtreeSize(graph, nodeKey)} below{children.length === 0 ? ', none vulnerable' : ''}
          </span>
        )}
      </div>
      {open && (
        <ul role="group">
          {children.map((c) => (
            <TreeRow
              key={c}
              graph={graph}
              nodeKey={c}
              pathKey={`${pathKey}>${c}`}
              ancestors={nextAncestors}
              depth={depth + 1}
              visible={visible}
              isOpen={isOpen}
              toggle={toggle}
              query={query}
              onOpenFinding={onOpenFinding}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

function worst(vulns: Vulnerability[]): Vulnerability {
  return [...vulns].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.risk_score - a.risk_score)[0]
}

function VulnMarker({ node, onOpen }: { node: GraphNode; onOpen: (key: string) => void }) {
  const w = worst(node.vulns)
  const meta = severityMeta(w.severity)
  return (
    <button
      onClick={() => onOpen(`${node.key}|${w.id}`)}
      title={`${node.vulns.length} finding(s), worst: ${meta.label} — open in Findings`}
      className="ml-1 inline-flex items-center gap-1 rounded border border-line bg-surface-2 px-1.5 py-px font-sans text-[11px] text-ink hover:border-accent"
    >
      <span aria-hidden className={`h-2 w-2 rounded-full ${TONE_BG[meta.tone]}`} />
      {node.vulns.length} {node.vulns.length === 1 ? 'finding' : 'findings'} · {meta.label}
    </button>
  )
}

/** For manifests without edges: direct vs transitive lists (or one list). */
function FlatList({ graph, onOpenFinding }: { graph: DepGraph; onOpenFinding: (key: string) => void }) {
  const all = [...graph.nodes.values()].sort((a, b) => b.vulns.length - a.vulns.length || a.key.localeCompare(b.key))
  const groups = graph.knowsDirect
    ? [
        { title: 'Direct', items: all.filter((n) => n.dep.direct) },
        { title: 'Transitive', items: all.filter((n) => n.dep.direct === false) },
      ]
    : [{ title: 'Packages', items: all }]
  return (
    <div className="rounded-xl border border-line bg-surface">
      <p className="border-b border-line px-4 py-3 text-xs text-ink-2">
        This manifest doesn't record which package depends on which, so there's no tree to draw.
        Scan a lockfile (<code className="font-mono">package-lock.json</code>) to see dependency paths.
      </p>
      {groups.filter((g) => g.items.length).map((g) => (
        <div key={g.title}>
          <h3 className="px-4 pt-3 text-xs font-semibold tracking-wide text-muted uppercase">
            {g.title} <span className="font-normal">({g.items.length})</span>
          </h3>
          <ul className="py-1 font-mono text-xs">
            {g.items.map((n) => (
              <li key={n.key} className="flex items-center gap-1.5 px-4 py-0.5">
                <span className={n.vulns.length ? 'font-semibold text-ink' : 'text-ink-2'}>
                  {n.dep.name}
                  <span className="font-normal text-muted">{n.dep.version ? `@${n.dep.version}` : ''}</span>
                </span>
                {n.vulns.length > 0 && <VulnMarker node={n} onOpen={onOpenFinding} />}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  )
}

/** Does `key` or anything below it match the search? (excludeSelf: only below) */
function matchesBelow(graph: DepGraph, key: string, q: string, excludeSelf = false): boolean {
  const seen = new Set<string>()
  const stack = excludeSelf ? [...(graph.nodes.get(key)?.children ?? [])] : [key]
  while (stack.length) {
    const k = stack.pop()!
    if (seen.has(k)) continue
    seen.add(k)
    if (k.toLowerCase().includes(q)) return true
    stack.push(...(graph.nodes.get(k)?.children ?? []))
  }
  return false
}
