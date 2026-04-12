# ARC Settle Profile

## Purpose

This profile closes `v2.37` by freezing the bounded `arc-settle` runtime that
ARC now actually ships over the official web3 contract family.

The later `v2.38` interop work does not widen `arc-settle` itself into a
generic bridge, scheduler, or gas-sponsorship system. Those overlays remain
separate bounded profiles on top of this runtime.

It covers four connected surfaces:

- the EVM settlement dispatcher over the official escrow and bond contracts
- the finality, timeout, refund, reversal, and bond-observation layer
- the bounded Solana-native Ed25519 settlement preparation lane
- the qualification and operator runbook surface that keeps custody and role
  assumptions explicit

Production operations for this runtime are frozen separately in
`docs/standards/ARC_WEB3_OPERATIONS_PROFILE.md`, with the settlement-specific
runtime example at `docs/standards/ARC_SETTLE_RUNTIME_REPORT_EXAMPLE.json`.

## Shipped Runtime Boundary

`arc-settle` now claims one bounded settlement runtime only:

- ERC-20 approval preparation plus escrow create, Merkle-proof release,
  dual-signature release, and timeout refund calls against the official
  `ArcEscrow` contract
- bond lock, release, impairment, and expiry calls against the official
  `ArcBondVault` contract
- deterministic mapping from approved ARC capital instructions into on-chain
  transaction sequences with fail-closed binding, rail, and jurisdiction checks
- tiered finality and dispute-window policy over chain confirmations, with
  explicit recovery actions for confirmation wait, dispute wait, reorg retry,
  refund, and manual review
- projection of observed chain state back into
  `arc.web3-settlement-execution-receipt.v1` without mutating prior signed ARC
  truth
- one bounded Solana settlement-preparation model that verifies ARC Ed25519
  receipts and key bindings locally, then emits a canonical
  `arc.settle.solana-release.v1` payload for parity checks
- one persistent Ganache runtime-devnet harness that qualifies the full local
  EVM lane end to end
- one generated end-to-end qualification bundle under
  `target/web3-e2e-qualification/` that proves FX-backed dual-sign execution,
  timeout refund, reorg recovery, and bond impairment/expiry behavior on the
  same bounded runtime
- bond-vault parity that keeps locked collateral distinct from reserve
  requirement metadata imported from signed ARC bond artifacts

## Machine-Readable Artifacts

- `docs/standards/ARC_SETTLE_FINALITY_REPORT_EXAMPLE.json`
- `docs/standards/ARC_SETTLE_SOLANA_RELEASE_EXAMPLE.json`
- `docs/standards/ARC_SETTLE_QUALIFICATION_MATRIX.json`
- `docs/standards/ARC_SETTLE_RUNTIME_REPORT_EXAMPLE.json`

## Operator Surface

The shipped operator surface is explicit and narrow:

- operators pin one settlement chain config with contract addresses, operator
  address, settlement token, and a tiered confirmation/dispute policy
- every dispatch must present one valid signed capital instruction on the
  `web3` rail plus one matching `settle` key-binding certificate
- Merkle-proof release remains subordinate to anchored ARC receipt truth from
  `arc-anchor`; `arc-settle` does not publish roots independently
- web3 settlement lanes require local durable receipt storage plus
  kernel-signed checkpoints; append-only remote receipt mirrors are not a
  supported substitute for Merkle or Solana evidence
- cross-currency conversion evidence stays explicit; when a lane marks FX
  evidence as required, the execution receipt must carry
  `authority = arc_link_runtime_v1` evidence from `arc-link` rather than from a
  hidden settlement-side oracle
- `./scripts/qualify-web3-e2e.sh` writes the generated partner-facing
  settlement evidence under `target/web3-e2e-qualification/`, and hosted
  staging copies the same family into
  `target/release-qualification/web3-runtime/e2e/`
- bond-vault reserve requirement fields mirror signed ARC bond terms for
  operator review, but on-chain locked and slashed balances still apply only to
  collateral
- Solana support is bounded to local verification and canonical instruction
  preparation, not live broadcast or indexing
- automation, CCIP coordination, and payment-interop surfaces may support this
  runtime, but they are documented separately and do not change the core
  dispatch or settlement authority model

## Related Interop Surfaces

`arc-settle` now interoperates with additional bounded `v2.38` overlays:

- `docs/standards/ARC_AUTOMATION_PROFILE.md` for settlement and bond watchdog
  jobs
- `docs/standards/ARC_CCIP_PROFILE.md` for cross-chain settlement
  coordination messages
- `docs/standards/ARC_PAYMENT_INTEROP_PROFILE.md` for x402, EIP-3009,
  Circle, and ERC-4337 compatibility

## Supported Lanes

The shipped settlement lanes are:

- EVM Merkle-proof release with anchored ARC receipt inclusion evidence
- EVM dual-signature release using the operator's registered settlement key
- EVM timeout refund after the configured deadline elapses
- EVM bond lifecycle observation for active, released, impaired, and expired
  vault state
- integrated FX-backed dual-sign execution plus recovery qualification over the
  generated `target/web3-e2e-qualification/` artifact family
- Solana-native Ed25519 settlement preparation and commitment-parity checks

## Failure Posture

`arc-settle` is fail closed by default.

Dispatch is denied when:

- the capital instruction signature, rail kind, jurisdiction, or destination
  does not match the intended settlement
- the key-binding certificate does not cover `settle` purpose, the configured
  chain, or the configured operator address
- the monetary amount cannot be represented exactly in the settlement token's
  minor units
- a required Merkle proof, receipt signature, or operator signature path is
  missing or invalid
- the evidence substrate is not durable, does not issue kernel-signed
  checkpoints, or cannot prove checkpoint signer equality with the receipt
  kernel key

Observed settlement remains explicit rather than optimistic:

- confirmation shortfall yields `awaiting_confirmations`
- a live dispute window yields `awaiting_dispute_window`
- canonical-chain drift yields `reorged`
- timeout refund yields `timed_out`
- release absence after a confirmed transaction yields `failed`
- bond impairment or expiry stays visible instead of implicit

## Non-Goals

This profile does not yet claim:

- permissionless settlement discovery or arbitrary-chain deployment
- automatic dispute adjudication or live dispute-event indexing
- solver-network batching, intent routing, or MEV-resistant settlement
- CCIP, CCTP, or other cross-chain fund transport that moves funds
  autonomously rather than coordinating bounded settlement state
- automatic gas sponsorship or hidden paymaster deductions; the shipped
  interop layer remains explicit compatibility only
- direct Solana transaction broadcast or on-chain Solana program verification

Those surfaces remain later milestones in the appended web3-runtime ladder.
