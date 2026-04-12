# Phase 156: arc-anchor Discovery, Operations, Compliance Notes, and Multi-Chain Qualification - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the milestone with discovery metadata, ownership semantics, operator
runbooks, qualification artifacts, and public-boundary rewrites that match the
actual bounded `arc-anchor` runtime.

</domain>

<decisions>
## Implementation Decisions

### Discovery And Ownership
- Emit one `did:arc` service artifact for the shipped anchor service.
- Keep root ownership on the operator address even when a delegate publisher is
  authorized.
- Describe Bitcoin and Solana as secondary evidence lanes, not replacements for
  the primary EVM proof.

### Qualification
- Keep the qualification matrix deterministic and local.
- Bind requirement closure to runtime tests, JSON artifact checks, and the
  existing devnet smoke rather than implying live external chain operations.
- Rewrite release and protocol docs to claim only the imported-proof and
  bounded-publication behaviors that now exist.

</decisions>

<code_context>
## Existing Code Insights

- the new `arc-anchor` crate now owns the runtime contract for all supported
  lanes
- release and protocol docs already describe the web3 artifact family and
  `arc-link` runtime boundary
- `docs/release/QUALIFICATION.md` is the correct place to bind the milestone to
  concrete verification commands

</code_context>

<deferred>
## Deferred Ideas

- live chain observers and promotion policy
- direct Bitcoin header verification or Solana RPC indexing
- automation or scheduling, which belongs to later milestones

</deferred>
