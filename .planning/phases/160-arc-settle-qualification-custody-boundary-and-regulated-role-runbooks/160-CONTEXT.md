# Phase 160: arc-settle Qualification, Custody Boundary, and Regulated-Role Runbooks - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Close `v2.37` with runtime qualification, custody and regulated-role
documentation, and public-boundary rewrites that match the implemented
`arc-settle` surface.

</domain>

<decisions>
## Implementation Decisions

### Qualification Boundary
- Use the persistent runtime-devnet test as the authoritative end-to-end proof
  for the local EVM lane.
- Keep machine-readable qualification in `docs/standards/` so later release
  and protocol docs can cite stable artifacts.

### Custody And Role Boundary
- Keep the operator role explicit as dispatcher and reconciler, not the owner
  of agent private keys.
- Keep escrow and bond-vault contracts as the bounded custody mechanism for
  this lane; ARC must not imply ambient regulated-custodian status.

### Public Closure
- Update release and protocol docs to claim only the runtime that is now
  implemented and tested.
- Advance planning state to `v2.38` only after the milestone audit and phase
  records are written.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-settle/tests/runtime_devnet.rs` already proves the local merkle,
  refund, and dual-signature paths against the official contract family.
- `docs/release/RELEASE_CANDIDATE.md`, `docs/release/QUALIFICATION.md`, and
  `spec/PROTOCOL.md` are the authoritative public-boundary docs used by prior
  milestone closure.
- `docs/research/ARC_SETTLE_RESEARCH.md` is broader than the shipped runtime,
  so this phase must document the bounded claim carefully.

</code_context>

<deferred>
## Deferred Ideas

- live testnet or mainnet partner proof
- event-driven monitoring or dispute indexers
- gas sponsorship, ERC-4337, CCIP, or automation work that belongs to `v2.38`

</deferred>
