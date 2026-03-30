# Phase 32 Research

## Findings

1. ARC is already the primary package and CLI surface, but the public narrative
   still starts from ARC in `README.md`, `docs/VISION.md`, and
   `docs/STRATEGIC_ROADMAP.md`.

2. The deep-research framing is sharper than the legacy transport-first
   language.
   `docs/research/DEEP_RESEARCH_1.md` positions ARC as a trust-and-economics
   control plane for governed actions, bounded spend, and verifiable receipts.

3. Release materials still describe the old milestone boundary.
   `docs/release/RELEASE_CANDIDATE.md` and `docs/release/RELEASE_AUDIT.md`
   still talk about `v2.3` rather than the current ARC rename state.

4. Qualification evidence must be rerun after the rename.
   ARC packaging, ARC-primary schema issuance, and ARC env aliases need actual
   proof from the release lane before `v2.5` can close honestly.

## Recommended Execution Shape

- Plan 32-01: rewrite the top-level product and strategy docs to ARC-first
  language aligned to `DEEP_RESEARCH_1.md`
- Plan 32-02: rerun the qualification / conformance lane on the renamed ARC
  surface
- Plan 32-03: record the migration and release-proof package, then close the
  milestone only if the evidence supports it
