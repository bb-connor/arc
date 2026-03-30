status: passed

# Phase 31 Verification

## Result

Phase 31 passed. ARC is now the primary protocol and artifact issuance identity
for the shipped rename surfaces, while the legacy PACT verification/import
paths remain explicit and tested.

## Evidence

- `cargo check -p arc-kernel -p arc-credentials -p arc-cli`
- `cargo test -p arc-kernel -- --nocapture`
- `cargo test -p arc-credentials -- --nocapture`
- `cargo test -p arc-cli --test certify --test passport --test provider_admin --test mcp_serve_http -- --nocapture`
- `cargo test -p arc-cli --test federated_issue --test evidence_export -- --nocapture`

## Notes

- new issuance now uses ARC-primary schema identifiers for DPoP, checkpoints,
  passports, verifier-policy artifacts, certification artifacts, and evidence
  export families where the rename contract said the schema move should happen
- legacy `arc.*` compatibility remains real in verification/import code paths
  instead of becoming an undocumented break
- `did:arc` remains the shipped DID method in this release, and `did:arc`
  stays explicitly future work rather than a half-implemented transition
