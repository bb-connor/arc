# chio-py Architecture Note

## Boundaries

- `src/chio/__init__.py` is the public Python SDK facade for hosted sessions,
  auth, receipt queries, nested callback helpers, and errors.
- `src/chio/invariants/` owns low-level cross-language compatibility checks
  for canonical JSON, hashing, signing, capabilities, and receipts.
- Signed tool manifests are admitted by the generated `chio.manifest.v1`
  models in `sdks/python/chio-sdk-python`, not by this package.
- `src/chio/mcp.py` verifies `chio.mcp.execution-evidence.v1` on MCP tool
  results (spec/PROTOCOL.md section 8.2.1). It depends on the `mcp` package
  only through the optional `mcp` extra.

## Security And API Constraints

- Canonical JSON byte generation and signature verification are independent
  checks.
