import { describe, expect, it } from 'vitest'
import { shortFix, upgradeCommand } from './fix'
import { dep } from './fixtures'

describe('upgradeCommand', () => {
  it.each([
    [dep('flask', { ecosystem: 'PyPI' }), '2.3.2', 'pip install "flask>=2.3.2"'],
    [dep('lodash', { ecosystem: 'npm', direct: true }), '4.17.21', 'npm install lodash@4.17.21'],
    [dep('github.com/gin-gonic/gin', { ecosystem: 'Go' }), '1.9.1', 'go get github.com/gin-gonic/gin@v1.9.1'],
  ])('gives an installable command for %s', (d, fixed, text) => {
    expect(upgradeCommand(d, fixed)).toEqual({ kind: 'command', text })
  })
  it('suggests an override for transitive npm packages', () => {
    expect(upgradeCommand(dep('qs', { direct: false }), '6.11.0').text).toContain('"overrides"')
  })
  it('gives an instruction for Maven and for commit-hash fixes', () => {
    expect(upgradeCommand(dep('a:b', { ecosystem: 'Maven' }), '2.17.1').kind).toBe('instruction')
    const sha = 'a'.repeat(40)
    expect(upgradeCommand(dep('x'), sha)).toMatchObject({ kind: 'instruction' })
    expect(shortFix(sha)).toBe('aaaaaaa')
  })
})

import { isWebUrl } from './url'

describe('isWebUrl (untrusted advisory links)', () => {
  it.each([
    ['https://github.com/advisories/GHSA-x', true],
    ['http://example.com', true],
    ['javascript:alert(1)', false],
    ['JaVaScRiPt:alert(1)', false],
    ['data:text/html,<script>', false],
    ['not a url', false],
  ])('%s → %s', (u, ok) => expect(isWebUrl(u)).toBe(ok))
})
