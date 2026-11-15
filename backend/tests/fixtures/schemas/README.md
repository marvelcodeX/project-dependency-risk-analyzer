Official JSON schemas, vendored so report validation runs offline in CI.

- `sarif-schema-2.1.0.json` — OASIS SARIF 2.1.0 (oasis-tcs/sarif-spec)
- `bom-1.5.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json` — CycloneDX 1.5
  (CycloneDX/specification); the BOM schema `$ref`s the other two by filename.

Update by re-downloading from those repos when bumping a spec version.
