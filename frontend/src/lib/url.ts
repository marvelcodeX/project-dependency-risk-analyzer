/** Advisory URLs are untrusted input: only http(s) links are ever rendered. */
export function isWebUrl(u: string): boolean {
  try {
    const { protocol } = new URL(u)
    return protocol === 'https:' || protocol === 'http:'
  } catch {
    return false
  }
}
