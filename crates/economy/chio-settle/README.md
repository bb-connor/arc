# chio-settle

`chio-settle` prepares Chio escrow and bond contract calls, observes EVM
transactions, and projects settlement execution artifacts. It also exports
receipt-observer contracts, payment compatibility helpers, and the public
`channel` module for signed channel state and economic continuity verification.

Capital and identity artifacts come from `chio-core`, `chio-credit`, and
`chio-web3`. Durable receipt/outcome storage and concrete observer or publisher
implementations belong to the integrating runtime.

## Usage

Prepare ERC-20 approval calldata offline with the default `web3` feature:

```rust
use chio_settle::prepare_erc20_approval;

let token = "0x1111111111111111111111111111111111111111";
let owner = "0x2222222222222222222222222222222222222222";
let spender = "0x3333333333333333333333333333333333333333";
let prepared = prepare_erc20_approval(token, owner, spender, 1_000_000)?;
assert_eq!(prepared.amount_minor_units, 1_000_000);
assert_eq!(prepared.call().to_address, token);
assert!(prepared.call().data.starts_with("0x095ea7b3"));
# Ok::<(), chio_settle::SettlementError>(())
```

This helper parses the spender address and encodes `approve`; it preserves
owner and token strings for later validation. Preparation performs no RPC or
broadcast. `submit_call` uses `eth_sendTransaction`, which requires an RPC node
that can send from the configured account. It rejects root publication,
escrow release/refund, and bond-exit selectors; those require a durable publisher.

## Settlement approvals

`verify_governed_approval` checks a signed `GovernedApprovalToken` against a
pinned approver, subject, request id, and intent hash. The intent must carry
`context.chioSettlementBinding` with schema `chio.settlement-binding.v1`.
It binds chain, payee, amount, rail token, settlement currency, dispatch id,
and capability id. The approval lifetime is at most one hour.

Both `build_x402_payment_requirements` and `evaluate_circle_nanopayment`
consume the resulting opaque `VerifiedApproval`. They refuse contract-pinned
bindings because these projections express token symbols only. x402 keeps
rail tokens separate from the settlement currency; Circle requires them to
match. Both lanes require an explicit dispatch capability id. A missing id
is refused without consuming the approval, even when the signed capability
id equals the dispatch id. Invalid lane inputs do not consume the approval.

The integrating runtime supplies the trusted clock and one shared
`ApprovalReplayStore` across both lanes. `InMemoryApprovalReplayStore` is
process-local. `chio-store-sqlite::SqliteApprovalReplayStore` retains consumed
request/intent pairs and a clock high-water mark across reopen. Artifact
issuance consumes approval before returning; a crash after consumption can
leave no returned artifact. This does not make external payment delivery
transactional or prove that a payment occurred.

## Features

| Feature | Default | Effect |
|---|---|---|
| `default` | Yes | Enables `web3`. |
| `web3` | Yes | Enables the entire crate API and optional ABI, HTTP, cryptographic, and Chio artifact dependencies. |

`--no-default-features` removes all public items. Payment, channel, Solana,
watchdog, and CCIP helpers share the `web3` gate.

## Guarantees

- `SettlementChainConfig::validate` checks required configuration, evidence
  flags, amount policy, a nonempty trusted kernel key set, and the
  dispatchable pinned-DNS RPC egress contract.
- `prepare_dual_sign_release` and `prepare_merkle_release` only prepare a
  release for a receipt whose `kernel_key` is a member of
  `kernel_authority.trusted_keys`, then verify it.
- `prepare_solana_settlement` requires a nonempty
  `SolanaSettlementConfig::kernel_authority`, refuses a receipt whose
  `kernel_key` is outside it, and accepts only a binding certificate naming
  that same trusted kernel key.
  Evidence flags declare integration prerequisites; they do not inspect a store.
- `SettlementHook` requires bounded local acceptance, concurrent-call safety,
  receipt-id deduplication across lease versions, and ordered batching by
  `(finalized_at, receipt_id)`. Observations arrive after signing and persistence;
  hooks must leave the receipt store unchanged. Integrators implement these
  obligations.
- `RetryPolicy::validate` bounds retry configuration. `classify_attempt`
  preserves typed failure reasons and terminates permanent or exhausted failures.
- `channel::ChannelSignatureV1::verify` binds body, signer id, key epoch, and key
  using canonical signed payloads. Verified channel wrappers require the
  corresponding funding, admission, transition, close, or release checks.

## Status

Implemented library surfaces include EVM call preparation/submission,
finality observation, finding-enforcement verification and publisher contracts,
channel verification, and payment compatibility artifacts. Solana helpers
verify carried binding/receipt signatures, check key equality, and prepare
canonical instruction data. They accept multiple signature algorithms and copy
the carried signature/key into Ed25519-labeled output. Callers must enforce
Ed25519 compatibility for the native lane. Preparation provides no broadcast.

CCIP and watchdog helpers model preparation and reconciliation; they provide
no scheduler or cross-chain broadcaster. Circle and paymaster helpers evaluate
supplied policy. Durable approval replay requires the shared SQLite backend;
deployed rail services and their payment execution remain caller work.

Unit and schema tests exercise these boundaries. Devnet tests require Node,
`ethers`, and `ganache`, and return early when prerequisites are unavailable.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Web3 artifacts](../chio-web3/README.md)
- [SQLite persistence](../../platform/chio-store-sqlite/README.md)
- [License](../../../LICENSE)
