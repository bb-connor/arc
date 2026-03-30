---
phase: 32
slug: qualification-documentation-and-launch-narrative
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 32 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Narrative/doc grep** | `rg -n "What ARC Is|ARC Protocol|Provable Agent Capability Transport|v2\\.3 production-candidate" README.md docs/VISION.md docs/STRATEGIC_ROADMAP.md docs/release/RELEASE_CANDIDATE.md docs/release/RELEASE_AUDIT.md docs/release/QUALIFICATION.md docs/release/GA_CHECKLIST.md` |
| **Schema/doc grep** | `rg -n "arc\\.dpop_proof\\.v1|arc\\.certify\\.check\\.v1|arc\\.agent-passport\\.v1|did:arc|did:arc" packages/sdk/arc-ts/src/dpop.ts packages/sdk/arc-ts/test/dpop.test.ts docs/DPOP_INTEGRATION_GUIDE.md docs/ARC_CERTIFY_GUIDE.md docs/AGENT_PASSPORT_GUIDE.md docs/DID_ARC_METHOD.md docs/standards/ARC_IDENTITY_TRANSITION.md spec/PROTOCOL.md` |
| **Release lane** | `./scripts/qualify-release.sh` |
| **SDK parity lane** | `./scripts/check-sdk-parity.sh` |
| **Planner confirmation** | `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 32-01 | ARC-01, ARC-07 | narrative/doc grep plus manual spot-check of README, VISION, strategy, release, DPoP, and certification guides |
| 32-02 | ARC-08 | `./scripts/qualify-release.sh` and `./scripts/check-sdk-parity.sh` |
| 32-03 | ARC-01, ARC-07, ARC-08 | roadmap analyze plus planning-doc grep after state updates |

## Coverage Notes

- this phase intentionally reran the release proof after the rename docs
  changed, rather than reusing earlier pre-closeout evidence
- hosted workflow sign-off remains an explicit release-audit item rather than
  being implied by local proof
- legacy `pact` aliases remain documented only where compatibility is still
  intended, not as the primary narrative

## Sign-Off

- [x] ARC is the coherent top-level identity across the release and product docs
- [x] release qualification passed after the final rename sweep
- [x] SDK parity passed after the final TS DPoP schema alignment
- [x] v2.5 planning state is ready for milestone audit and archive

**Approval:** completed
