# Phase 29 Research

## Sources Read

- `docs/research/DEEP_RESEARCH_1.md`
- `docs/DID_ARC_METHOD.md`
- `spec/PROTOCOL.md`
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md`
- `.planning/research/ARC_RENAME_AND_GAP_SYNTHESIS.md`

## Key Findings

1. `ARC` is a materially stronger name than `ARC` for the current thesis.
   The research anchors the product around attested rights, bounded spend, and
   verifiable receipts rather than transport alone.

2. The rename is not just branding.
   The repo contains `ARC` in crate names, CLI commands, SDK packages, docs,
   standards drafts, and signed artifact families. A contract is required
   before mass edits begin.

3. `did:arc` is the hardest edge.
   It is already shipped and used in portable-trust flows. A reasonable path is
   to freeze `did:arc` as a legacy compatibility method for historical
   artifacts, add `did:arc` for new issuance later, and require verifiers to
   support both during transition.

4. Schema IDs need dual handling.
   New ARC-branded artifacts can use `arc.*` identifiers once Phase 31 lands,
   but verifiers/importers should continue accepting legacy `arc.*`
   identifiers indefinitely for historical data.

5. CLI and SDK compatibility should be time-bounded.
   The primary user-facing surface should become `arc`, but one compatibility
   cycle for legacy `pact` entrypoints is the safer migration contract.

## Recommended Decisions for Phase 29

- `arc` CLI -> legacy alias for one compatibility cycle after `arc` becomes
  primary
- `ARC` docs/specs -> ARC as primary narrative as soon as Phase 32 lands
- `did:arc` -> frozen compatibility method; `did:arc` introduced for new
  issuance in Phase 31 or later
- `arc.*` schema IDs -> accepted indefinitely for old artifacts; new issuance
  may move to `arc.*` once verifiers/importers are dual-stack
- repo/crate/package rename -> Phase 30 implementation after inventory and
  migration docs are in place
