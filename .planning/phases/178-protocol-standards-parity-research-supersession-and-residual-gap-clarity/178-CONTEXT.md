# Phase 178: Protocol/Standards Parity, Research Supersession, and Residual Gap Clarity - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Align the authoritative protocol and standards docs with the shipped web3
artifact family, mark older research docs as superseded where the runtime now
exists, and make the remaining public non-goals explicit.

</domain>

<decisions>
## Implementation Decisions

### Shipped Surface First
- treat `docs/standards/ARC_WEB3_PROFILE.md` and `spec/PROTOCOL.md` as the
  authoritative public boundary
- align those docs around the actual runtime/package that exists locally,
  rather than the earlier v2.30 artifact-only wording

### Research As Historical Input
- keep the late-March research papers intact as research records
- add short realization notes that point readers at the shipped runtime,
  standards, and contract names instead of rewriting those papers in place

### Residual Gap Discipline
- explicitly state the one mutable contract surface
- explicitly state that hosted qualification remains required for publication
- keep unattended rollout, permissionless discovery, and ambient MCP trust
  expansion out of scope

</decisions>

<code_context>
## Existing Doc Insights

- `docs/standards/ARC_WEB3_PROFILE.md` still centered the realized overlay on
  `v2.39` and did not clearly carry forward the `v2.40` hardening or `v2.41`
  hosted-proof closure
- `docs/standards/ARC_WEB3_CONTRACT_PACKAGE.json` still deferred a
  `live-mainnet-deployment-runner` capability even though phase `174` shipped
  a reviewed-manifest promotion runner
- partner-facing docs still implied uniform contract immutability even though
  the identity registry remains the one owner-managed mutable contract
- several research/decision docs still used older names like
  `ArcReceiptVerifier` or `ArcSettleRegistry` without a bridge to the shipped
  `IArcRootRegistry` and `IArcIdentityRegistry` surfaces

</code_context>

<deferred>
## Deferred Ideas

- GSD tooling repair and assurance-artifact backfill remain phase `179`
- oversized runtime boundary decomposition remains phase `180`

</deferred>
