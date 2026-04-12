# Phase 161: Chainlink Functions Proof Verification and EVM Ed25519 Fallback Strategy - Context

**Gathered:** 2026-04-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the missing EVM-side Ed25519 verification gap with one bounded
Functions-based fallback that audits ARC receipts without turning DON
execution into settlement authority.

</domain>

<decisions>
## Implementation Decisions

### Fallback Posture
- Keep the Functions path audit-only and subordinate to canonical ARC receipt
  truth.
- Bound the path by batch size, request size, callback gas, return size, and
  notional-value ceilings.

### Supported Verification Modes
- Support batch audit and spot-check style receipt verification only.
- Keep unsupported direct fund-release and arbitrary DON execution paths as
  explicit non-goals.

### Qualification
- Qualify both the accepted verified path and the rejected or mismatched
  response path inside `arc-anchor`.
- Publish concrete request and response examples so later automation and CCIP
  docs can reference the same fallback contract.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-anchor/src/lib.rs` is already the bounded place for imported or
  secondary proof logic, so the Functions fallback belongs there.
- `docs/research/ARC_LINK_FUTURE_TRACKS.md` and
  `docs/research/ARC_WEB3_TRUST_BOUNDARY_DECISIONS.md` both require this lane
  to stay explicit about trust and cost tradeoffs.
- `arc-settle` and `arc-anchor` already rely on canonical receipt and proof
  artifacts, so the fallback must consume those artifacts rather than invent a
  second truth family.

</code_context>

<deferred>
## Deferred Ideas

- native Ed25519 verification precompiles on EVM
- direct settlement release gated by Functions
- generic DON compute workflows beyond the bounded receipt-audit lane

</deferred>
