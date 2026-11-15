// Per-ecosystem remediation commands for the "copy fix command" button.

import type { Dependency } from '../api'

/** A git commit hash is sometimes OSV's "fixed" event: not installable. */
export function isCommitHash(v: string): boolean {
  return /^[0-9a-f]{40}$/i.test(v)
}

export function shortFix(v: string): string {
  return isCommitHash(v) ? v.slice(0, 7) : v
}

/**
 * The command that upgrades `dep` to `fixed`, or a plain instruction when the
 * ecosystem has no one-liner (Maven) or the fix isn't a release (commit hash).
 */
export function upgradeCommand(
  dep: Dependency,
  fixed: string,
): { kind: 'command' | 'instruction'; text: string } {
  if (isCommitHash(fixed)) {
    return {
      kind: 'instruction',
      text: `Fixed in commit ${fixed.slice(0, 7)} — no release yet; upgrade once one includes it.`,
    }
  }
  switch (dep.ecosystem) {
    case 'PyPI':
      return { kind: 'command', text: `pip install "${dep.name}>=${fixed}"` }
    case 'npm':
      return {
        kind: 'command',
        // Direct deps: install the fix. Transitive: needs an override, since
        // the parent package decides the version.
        text:
          dep.direct === false
            ? `npm update ${dep.name}  # if blocked, add "overrides": {"${dep.name}": "${fixed}"}`
            : `npm install ${dep.name}@${fixed}`,
      }
    case 'Go':
      return { kind: 'command', text: `go get ${dep.name}@v${fixed.replace(/^v/, '')}` }
    case 'Maven':
      return {
        kind: 'instruction',
        text: `Set <version>${fixed}</version> for ${dep.name} in pom.xml (or its <dependencyManagement>).`,
      }
    default:
      return { kind: 'instruction', text: `Upgrade ${dep.name} to ${fixed} or later.` }
  }
}
