import { describe, expect, it } from 'vitest'
import { buildGraph, keysLeadingToVulns, pathTo, subtreeSize } from './graph'
import { dep, scan, vuln } from './fixtures'

// project → express → body-parser → qs(vulnerable); project → eslint → chalk
const s = scan([
  [dep('express', { direct: true, depends_on: ['body-parser@1.0.0', 'missing@9.9.9'] }), []],
  [dep('body-parser', { direct: false, depends_on: ['qs@1.0.0'] }), []],
  [dep('qs', { direct: false }), [vuln('GHSA-qs')]],
  [dep('eslint', { direct: true, depends_on: ['chalk@1.0.0'] }), []],
  [dep('chalk', { direct: false }), []],
])

describe('buildGraph', () => {
  it('uses direct deps as roots and drops edges to unknown packages', () => {
    const g = buildGraph(s)
    expect(g.roots).toEqual(['eslint@1.0.0', 'express@1.0.0'])
    expect(g.nodes.get('express@1.0.0')!.children).toEqual(['body-parser@1.0.0'])
    expect(g.hasEdges && g.knowsDirect).toBe(true)
  })
  it('falls back to in-degree roots when directness is unknown (lockfile v1)', () => {
    const v1 = scan([
      [dep('a', { depends_on: ['b@1.0.0'] }), []],
      [dep('b'), []],
    ])
    expect(buildGraph(v1).roots).toEqual(['a@1.0.0'])
  })
  it('treats every package as a root when there is no graph at all', () => {
    const flat = scan([[dep('flask'), []], [dep('django'), []]])
    expect(buildGraph(flat).roots).toEqual(['django@1.0.0', 'flask@1.0.0'])
  })
})

describe('pathTo', () => {
  const g = buildGraph(s)
  it('finds the shortest chain from a direct dependency', () => {
    expect(pathTo(g, 'qs@1.0.0')).toEqual(['express@1.0.0', 'body-parser@1.0.0', 'qs@1.0.0'])
  })
  it('returns the package alone when it is direct', () => {
    expect(pathTo(g, 'express@1.0.0')).toEqual(['express@1.0.0'])
  })
  it('returns null for unknown packages', () => {
    expect(pathTo(g, 'nope@1')).toBeNull()
  })
})

describe('keysLeadingToVulns', () => {
  it('marks the vulnerable package and every ancestor, nothing else', () => {
    expect([...keysLeadingToVulns(buildGraph(s))].sort()).toEqual([
      'body-parser@1.0.0', 'express@1.0.0', 'qs@1.0.0',
    ])
  })
  it('is correct when the graph has a cycle', () => {
    const cyc = scan([
      [dep('a', { direct: true, depends_on: ['b@1.0.0'] }), []],
      [dep('b', { direct: false, depends_on: ['c@1.0.0'] }), []],
      [dep('c', { direct: false, depends_on: ['b@1.0.0'] }), [vuln('X')]],
    ])
    expect([...keysLeadingToVulns(buildGraph(cyc))].sort()).toEqual(['a@1.0.0', 'b@1.0.0', 'c@1.0.0'])
  })
})

it('subtreeSize counts distinct descendants', () => {
  const g = buildGraph(s)
  expect(subtreeSize(g, 'express@1.0.0')).toBe(2)
  expect(subtreeSize(g, 'qs@1.0.0')).toBe(0)
})
