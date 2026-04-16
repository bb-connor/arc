# Review Remediation Package

Date: 2026-04-13

This folder converts the adversarial review of ARC into a concrete
remediation package.

Each document covers one hole:

- the current problem
- the evidence boundary today
- why current claims overreach
- the target end-state required to make the stronger claim true
- the architecture, spec, proof, validation, and milestone work needed to get there

## Documents

- [13-ship-blocker-ladder.md](./13-ship-blocker-ladder.md): release-triage ladder splitting bounded-ARC blockers, stronger-security blockers, and comptroller-thesis blockers into P0/P1/P2
- [14-bounded-arc-pre-ship-checklist.md](./14-bounded-arc-pre-ship-checklist.md): authoritative pre-ship checklist for the bounded ARC release boundary, mapped to `v3.18`
- [15-vision-gap-map.md](./15-vision-gap-map.md): strongest ARC vision claims mapped to current evidence and the exact work required to make each stronger claim literally true
- [16-vision-closure-execution-board.md](./16-vision-closure-execution-board.md): phased execution board turning the vision-gap debate into waves, owners, gates, and merge order
- [17-post-closure-execution-board.md](./17-post-closure-execution-board.md): hard-gated follow-on board sequencing Wave 0 reporting truth closure before trust-anchored transparency publication and the budget-authority protocol
- [01-formal-verification-remediation.md](./01-formal-verification-remediation.md): formal model scope, refinement to Rust, and proof-gated claim discipline
- [02-delegation-enforcement-remediation.md](./02-delegation-enforcement-remediation.md): runtime delegation-chain validation, attenuation enforcement, and lineage completeness
- [03-runtime-attestation-remediation.md](./03-runtime-attestation-remediation.md): verifier-backed runtime assurance from raw evidence to kernel admission
- [04-provenance-call-chain-remediation.md](./04-provenance-call-chain-remediation.md): authenticated provenance, governed call-chain truth, and verified lineage classes
- [05-non-repudiation-remediation.md](./05-non-repudiation-remediation.md): transparency-log semantics, key anchoring, consistency proofs, and anti-equivocation
- [06-authentication-dpop-remediation.md](./06-authentication-dpop-remediation.md): sender-constrained auth, DPoP, subject binding, and replay robustness
- [07-ha-control-plane-remediation.md](./07-ha-control-plane-remediation.md): consensus-grade trust control, failover correctness, and authority key management
- [08-distributed-budget-remediation.md](./08-distributed-budget-remediation.md): linearizable budgets, spend invariants, and truthful exposure accounting
- [09-session-isolation-remediation.md](./09-session-isolation-remediation.md): hosted MCP isolation profiles, privilege-shrink safety, and shared-owner boundaries
- [10-economic-authorization-remediation.md](./10-economic-authorization-remediation.md): payer/payee binding, ex ante settlement commitment, metering, and honest economic semantics
- [11-reputation-federation-remediation.md](./11-reputation-federation-remediation.md): issuer independence, subject continuity, Sybil resistance, and bounded federation
- [12-standards-positioning-remediation.md](./12-standards-positioning-remediation.md): protocol-vs-product boundaries, interoperable scope, and evidence-based comparative claims

## Suggested Order

Start with the release-triage memo if the immediate question is "what blocks
shipping?" then go to the underlying remediations:

- [13-ship-blocker-ladder.md](./13-ship-blocker-ladder.md)
- [14-bounded-arc-pre-ship-checklist.md](./14-bounded-arc-pre-ship-checklist.md)

Start with the vision map if the immediate question is "which parts of the full
ARC thesis are already true, and what exact work remains?":

- [15-vision-gap-map.md](./15-vision-gap-map.md)
- [16-vision-closure-execution-board.md](./16-vision-closure-execution-board.md)
- [17-post-closure-execution-board.md](./17-post-closure-execution-board.md)

Start with the foundation docs first:

- [12-standards-positioning-remediation.md](./12-standards-positioning-remediation.md)
- [01-formal-verification-remediation.md](./01-formal-verification-remediation.md)
- [02-delegation-enforcement-remediation.md](./02-delegation-enforcement-remediation.md)
- [06-authentication-dpop-remediation.md](./06-authentication-dpop-remediation.md)
- [04-provenance-call-chain-remediation.md](./04-provenance-call-chain-remediation.md)

Then address the systems and evidence substrate:

- [07-ha-control-plane-remediation.md](./07-ha-control-plane-remediation.md)
- [08-distributed-budget-remediation.md](./08-distributed-budget-remediation.md)
- [05-non-repudiation-remediation.md](./05-non-repudiation-remediation.md)
- [09-session-isolation-remediation.md](./09-session-isolation-remediation.md)
- [03-runtime-attestation-remediation.md](./03-runtime-attestation-remediation.md)

Then take the economic and networked-trust layers:

- [10-economic-authorization-remediation.md](./10-economic-authorization-remediation.md)
- [11-reputation-federation-remediation.md](./11-reputation-federation-remediation.md)

## Interpretation Rule

These docs are not wording-softening exercises. The standard used throughout is:

- either narrow the public claim to match the shipped evidence boundary
- or implement the missing machinery needed to make the stronger claim true
