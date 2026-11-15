# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub: go to the repository's **Security** tab →
**Report a vulnerability**. You'll get an acknowledgement within a few days, and a fix or a
mitigation plan once the report is confirmed. Credit is given in the release notes unless you
prefer otherwise.

Useful details: the affected version (`GET /api/health` shows it), how to reproduce, and the
impact you expect.

## Supported versions

Only the latest release receives security fixes.

## Deployment guidance

Soteria-AI is designed to run **locally or on a trusted network**:

- **The API has no authentication.** Anyone who can reach it can run scans and read all scan
  history. Do not expose it to the internet; bind it to `localhost` or put it behind an
  authenticating reverse proxy.
- **Outbound requests** go only to OSV (`api.osv.dev`), the CISA KEV feed, the PyPI and npm
  registries (to resolve unpinned versions), and your local Ollama server. Scanned code and
  manifests are never sent to an AI service in the cloud.

## How untrusted input is handled

Everything a user uploads, and everything returned by vulnerability databases, is treated as
untrusted:

- **Manifests** are parsed, never executed. `pom.xml` is parsed with `defusedxml` (no entity
  expansion); uploads are capped at 5 MB and must be UTF-8.
- **Source code** for reachability is only parsed (Python `ast`, JS/TS import statements) —
  never imported or run.
- **Advisory text** (summaries, details, reference URLs) is escaped in every report; the HTML
  report is served with a `default-src 'none'` Content-Security-Policy; the UI only renders
  `http(s)` reference links.
- **The CLI and GitHub Action** read files from the checked-out repository and make the same
  outbound requests; they need no secrets beyond the token GitHub provides for SARIF upload.
