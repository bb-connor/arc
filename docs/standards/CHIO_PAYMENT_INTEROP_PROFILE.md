# Chio Payment Interop Profile

## Purpose

This profile closes phase `164` by freezing Chio's bounded machine-payment and
gas-abstraction compatibility layer.

These surfaces sit on top of governed Chio dispatch and settlement truth. They
never replace signed receipts, explicit approval context, or the official web3
dispatch contract.

## Shipped Boundary

Chio now ships four bounded payment-interop capabilities:

- projection of one governed settlement dispatch into an x402 payment-requirement
  object
- preparation of one EIP-3009 `transferWithAuthorization` digest for
  explicit gasless token movement review
- evaluation of one Circle nanopayment candidate only when operator-managed
  custody is explicit
- evaluation of one ERC-4337/paymaster compatibility record only when gas
  sponsorship and reimbursement remain within bounded policy

## Supported Guardrails

The shipped interop layer requires:

- a facilitator URL and resource identifier for x402
- explicit accepted-token lists rather than ambient token discovery
- explicit chain allowlists for Circle-managed custody and paymaster use
- explicit reimbursement ceilings for paymaster compatibility
- explicit settlement-side deduction semantics for any sponsored gas posture

## Reference Artifacts

- `docs/standards/CHIO_X402_REQUIREMENTS_EXAMPLE.json`
- `docs/standards/CHIO_EIP3009_TRANSFER_WITH_AUTHORIZATION_EXAMPLE.json`
- `docs/standards/CHIO_CIRCLE_NANOPAYMENT_EXAMPLE.json`
- `docs/standards/CHIO_4337_PAYMASTER_COMPAT_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json`

## Failure Posture

The interop layer fails closed when:

- an x402 surface omits facilitator, resource, or accepted-token scope
- Circle-managed custody is not explicitly declared
- the dispatch chain or token falls outside the bounded policy
- the candidate amount exceeds the bounded nanopayment ceiling
- requested gas sponsorship or reimbursement exceeds the bounded paymaster
  policy
- gas reimbursement would be treated as an implicit hidden deduction

## Non-Goals

This profile does not claim:

- a generic payment-facilitator marketplace
- implicit custody handoff to Circle or another provider
- universal gas sponsorship for all Chio calls
- mutation of signed Chio receipts to reflect off-protocol facilitator state

The shipped layer is interoperability only.

## Recompute-Bound Proof Projections (M2-15)

The sections above freeze the outbound payment-requirement projection layer.
This section states the inbound invariant that governs how Chio treats the
x402, ACP-Commerce, ACP-Client, and AP2 payment standards when they arrive as
evidence.

Chio carries these external payment standards as detached, digest-bound proof
projections for display and interoperability. A carried external object is
never a Chio proof and never a Chio grant. The single proof lane is recompute:
a Chio verifier recomputes the committed state for itself and trusts no
producer-asserted or witnessed value.

### Payment success is not authorization

A settled payment satisfies a payment precondition only. It never grants a
tool call. Tool-call permission comes from the capability and governance lane,
never from a settlement receipt.

Recompute is the sole proof lane:

- `verify_anchor_inclusion_proof` in
  `crates/economy/chio-web3/src/anchors.rs` is the verifier-side mirror of the
  on-chain `getRoot` and `verifyInclusionDetailed` readback. It takes the
  committed Merkle root only from the kernel-signed checkpoint statement,
  recomputes the receipt leaf from the canonical receipt body, and re-walks
  the audit path. A merely asserted value is refused.
- `verify_public_settlement_proof` in
  `crates/economy/chio-web3/src/settlement_proof.rs` returns a
  `PublicSettlementVerifierReport` whose verdict is `verified` and never
  `authorized`. Every claim it can emit lives under the
  `claim.public_settlement.*` prefix (for example
  `CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED`). The report carries no
  capability grant.

Two keystone negatives (M2-2, WS-CL-RECOMPUTE-GATE) pin this in code:

- `crates/economy/chio-web3/src/tests.rs`, test
  `verified_x402_settlement_receipt_does_not_authorize_tool_call`: a fully
  verified x402 settlement receipt emits only `claim.public_settlement.*`
  claims, none of which contains `tool_call`, `capability`, `authoriz`, or
  `invoke`, and the verdict is never `authorized`.
- `crates/tooling/chio-conformance/tests/eas_attestation_not_anchoring_inclusion_proof.rs`:
  an external EAS/SAS attestation that merely asserts a root is not admissible
  as a `chio.anchor-inclusion-proof.v1`. Splicing the asserted root fails
  closed at the inclusion layer, and committing it everywhere breaks the
  kernel-signed checkpoint signature. The fixture is
  `docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json`.

### The mandate allowance ledger (allowlist)

A payment standard is admitted only against a `chio-commerce-order` mandate
allowance ledger, schema `chio.commerce.mandate-allowance-ledger.v1`, defined
in `crates/platform/chio-commerce-order/src/mandate.rs`. The ledger is the
allowlist. It binds one order id, merchant subject, currency, maximum amount,
quote digest, validity window, and occurrence count, then pins one digest per
carried standard:

- `ap2_checkout_mandate_hash` and `ap2_payment_mandate_hash`
- `acp_delegated_payment_token_hash`
- `x402_payment_requirements_hash`

`validate_mandate_ledger` recomputes each protocol projection digest from the
carried payload bytes and fails closed on any order, amount, currency, quote,
window, or occurrence mismatch. `validate_supported_projection_protocol`
admits only the `ap2`, `acp-commerce`, `x402`, and `chio` protocol ids and
rejects every other id.

### Carried via the Agent Web proof envelope

The display and interoperability projection is the
`chio.agent-web-proof-envelope.v1` object verified by `verify_agent_web_interop`
in `crates/platform/chio-agent-web-interop/src/lib.rs`. The envelope binds a
digest of the external subject, a projection manifest
(`chio.agent-web.external-projection-manifest.v1`), and Chio receipt
references, then emits a `chio.agent-web.interop-verifier-report.v1`.

Each carried standard is a registered source protocol in
`crates/platform/chio-agent-web-interop/src/protocols.rs`:

- `x402`, external subject schema `external.x402.payment.v1`, source version `0.5`
- `ap2`, external subject schema `external.ap2.mandate-chain.v1`, source version `0.2`
- `acp-commerce`, external subject schema `external.acp-commerce.checkout.v1`, source version `2026-06`
- `acp-client`, external subject schema `external.acp-client.permission.v1`, source version `v1`

Every projection manifest MUST list its protocol limitation under
`unsupported_claims`, and the verifier rejects any policy that demands a
`claim.external.*` claim through `reject_required_external_authority_claims`.
The per-protocol `claim.external.<protocol>_is_chio_authority` limitations are
defined in `crates/platform/chio-agent-web-interop/src/claims.rs`. The envelope
must also carry `claim.agent_web.sidecar_not_native_authority`, so a carried
object can never be promoted into a native Chio proof.

### Live money movement is gated and testnet-only

The settlement runtime in `crates/economy/chio-settle` compiles behind
`#![cfg(feature = "web3")]`, and its evidence substrate (`EvidenceSubstrateMode`
in `crates/economy/chio-settle/src/config.rs`) defaults to
`LocalKernelSignedCheckpointV1`: a local kernel-signed checkpoint recomputed
offline, not a live chain readback.

The live Coinbase CDP money-movement leg is opt-in and testnet-only:

- The public settlement verifier (`PublicSettlementVerifierTrust` in
  `crates/economy/chio-web3/src/settlement_proof.rs`) carries a
  `mainnet_blocked` flag and an explicit `allowed_chain_ids` allow-list, so
  production chains are refused unless an operator opts in.
- Live CDP server-wallet writes require an operator to run `cdp env live` with
  a testnet-only key, per
  `docs/standards/CHIO_WEB3_OPERATOR_ENVIRONMENT.example` (Base Sepolia RPC and
  a testnet deployer key).
- Promotion to a production chain is gated by
  `docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json`, which requires a passing
  Base Sepolia rehearsal smoke report before any mainnet approval artifact is
  prepared.

Nothing on the live money-movement leg runs implicitly. It is provisioned by
the operator, starts on testnet, and clears the promotion gates first.

## Recompute-Bound Reference Symbols

- `crates/economy/chio-web3/src/anchors.rs`: `verify_anchor_inclusion_proof`,
  `AnchorInclusionProof`, schema `chio.anchor-inclusion-proof.v1`
- `crates/economy/chio-web3/src/settlement_proof.rs`:
  `verify_public_settlement_proof`, `PublicSettlementVerifierReport`,
  `PublicSettlementVerifierTrust`, schema
  `chio.public-settlement-verifier-report.v1`
- `crates/platform/chio-agent-web-interop/src/lib.rs`:
  `verify_agent_web_interop`, schema `chio.agent-web-proof-envelope.v1`
- `crates/platform/chio-commerce-order/src/mandate.rs`:
  `validate_mandate_ledger`, schema `chio.commerce.mandate-allowance-ledger.v1`
- `crates/economy/chio-web3/src/tests.rs`:
  `verified_x402_settlement_receipt_does_not_authorize_tool_call`
- `crates/tooling/chio-conformance/tests/eas_attestation_not_anchoring_inclusion_proof.rs`
