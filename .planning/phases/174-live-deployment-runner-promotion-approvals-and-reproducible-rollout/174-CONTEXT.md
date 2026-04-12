# Phase 174: Live Deployment Runner, Promotion Approvals, and Reproducible Rollout - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Turn ARC's reviewed deployment manifests into a bounded promotion lane that can
deploy the official contract family deterministically, require explicit
approval artifacts, emit deployment and rollback records, and stage that proof
through the hosted release artifact bundle.

</domain>

<decisions>
## Implementation Decisions

### Reviewed Manifest Runner
- build the promotion runner around reviewed manifest files instead of
  widening the shipped `*.template.json` files into live rollout state
- use CREATE2 address planning from the reviewed manifest so promotion reports
  can prove reproducibility before and after deployment
- keep local rehearsal on Ganache and live rollout on operator-owned RPC
  credentials outside the repo

### Role-Aware Approval And Signers
- require one approval artifact that binds reviewed manifest path and hash,
  contract release id, deployment policy id, CREATE2 mode, factory address or
  factory mode, and salt namespace
- make the runner role-aware: deployer, registry admin, operator, and price
  admin may be distinct signers in non-local rollout, and mismatched signer
  material fails closed
- keep local qualification on fixed known keys so replayed runs stay
  deterministic

### Rollback And Hosted Evidence
- local rehearsal uses an EVM snapshot and explicit rollback-plan output so
  failed promotion can prove `rollback_executed: true`
- live rollback stays replacement-oriented and explicit rather than implying
  proxy upgrade or hidden revert behavior
- stage runtime and promotion artifacts together under
  `target/release-qualification/web3-runtime/` so hosted reviewers see one
  stable bundle

</decisions>

<code_context>
## Existing Code Insights

- the contract package already had deterministic manifests and a local-devnet
  smoke lane, but no reviewed-manifest promotion runner
- hosted release qualification already staged runtime qualification artifacts,
  which made it natural to add a `promotion/` subtree under the same bundle
- `ArcRootRegistry.registerDelegate` is operator-only, so the promotion runner
  had to respect reviewed role boundaries instead of assuming one admin signer
  could perform every post-deploy action

</code_context>

<deferred>
## Deferred Ideas

- generated runtime reports and exercised emergency controls in phase `175`
- integrated recovery and partner-facing end-to-end settlement proof in phase
  `176`
- release-governance and planning-tool truth repair in `v2.42`

</deferred>
