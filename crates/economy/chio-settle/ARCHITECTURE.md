# chio-settle architecture

## Responsibility and boundary

The crate exports EVM preparation, submission, confirmation, and observation
functions; payment compatibility helpers;
finding-enforcement verification and publishers; and `pub mod channel`.
Other implementation modules are private, with selected items re-exported at
the crate root. `#![cfg(feature = "web3")]` gates the whole library.

The library owns prepared call data and verification results. A runtime owns
RPC accounts, deployed contracts, trusted policy, durable receipt storage,
outcome leases, and publisher effects. The settlement hook, outcome-store
and retry vocabulary lives in `chio-settle-types`.

## Structure

| Module | Responsibility |
|---|---|
| `config` | Chain, amount-tier, oracle, evidence-substrate, and local deployment configuration. |
| `evm/{prepare,finalize,decode,sign,types}` | Solidity ABI calls, receipt/event decoding, proof and identity checks, signing, and prepared values. |
| `observe` | Escrow/bond snapshots, confirmation/dispute-window assessment, execution receipt projection, and recovery actions. |
| `payments` and `payments_approval` | x402 approval binding and Circle/paymaster checks. |
| `finding_enforcement/{verify,plan,publish,reconcile,observation_source,remote_http}` | Pinned authority and collateral verification, impairment intent preparation, remote adapters, and post-dispatch recovery. |
| `channel` | Asset/funding/open artifacts, signatures, reservations, state, lifecycle projections, replay, terminal outcomes, disputes, close, and release authorization. |
| `solana`, `ccip`, `automation`, `ops` | Instruction preparation, coordination messages, watchdog evidence, and operator controls/reports. |
| `input` | Bounded original-byte canonical JSON decoding for ingress. |

## Data and control flow

`prepare_web3_escrow_dispatch` validates chain configuration, the capital
instruction, and settlement identity binding. It derives the expected escrow
id with an RPC call and builds a `PreparedEscrowCreate`. `prepare_bond_lock`
similarly constructs bond-vault terms, preserving collateral and reserve
requirement separately. `prepare_erc20_approval` is an offline ABI helper;
its validation is limited to parsing the spender address.

`submit_call` sends supported prepared calls through `eth_sendTransaction`.
It rejects root-publication, escrow-release/refund, and bond-exit selectors
before RPC. These operations require a durable publisher integration.
`confirm_transaction` polls at most 100 times, waits 100 ms between empty
results, and decodes receipt/block data. RPC latency contributes to total time.
Finalizers recover identities from emitted events; bond finalization also
checks the bond and facility hashes against the prepared lock.

`inspect_finality_for_receipt` compares the observed block hash with the current
chain, confirmation depth with the amount tier, and supplied observation time
with the dispute deadline. Without a time override, it uses the transaction's
observed timestamp. `project_escrow_execution_receipt` combines finality and
escrow state, then validates the resulting web3 execution artifact.

For observer work, the backend claims a due receipt under a version and lease.
The hook receives `SettlementIdempotencyKey`; the runtime converts its result
into `SettlementRoutingInput` and commits through `record_claimed_outcome`.
`classify_attempt` returns acceptance, skip, retry scheduling, or dead lettering.
The backend must atomically enforce the exact unexpired claim and persist the
transition; the pure classifier does no storage, sleeping, or policy validation.

Channel admission composes verified open/funding and reservation artifacts
with economic state views. Projection helpers describe reservation, dispatch,
cancellation, and terminal batch transitions. Replay descriptors retain the
inputs and pinned authority needed to verify those transitions again.
Close and release verification bind the effective close, lifecycle fences,
amount allocation, and verified FROST authorization before EVM preparation.

## Trust and invariants

`SettlementChainConfig::validate` requires nonempty fields, amount policy,
evidence flags, a nonempty and duplicate-free `kernel_authority.trusted_keys`
set, and a dispatchable pinned-DNS `HttpEgressContract` matching the RPC URL.
`prepare_dual_sign_release` and `prepare_merkle_release` refuse a receipt
whose `kernel_key` is not in `kernel_authority.trusted_keys` before they
verify the receipt or its anchor proof. RPC helpers use the contract-aware
HTTP client. Evidence flags express required integration posture; setting them
does not create or inspect durable receipts, checkpoints, or signer equality.

Instruction readiness checks that the completion-flow row id from
`chio-settle-types` names its governed receipt before escrow preparation. The
conversion identifies a row; it does not load durable state.

Finding dispatch verification uses independently pinned, distinct signing roles,
retained lifecycle policy, current authority status, fresh finalized collateral,
exact snapshot digest and allocation binding, and permitted destinations.
Reconciliation authenticates historical dispatched inputs without renewing
fresh dispatch authority. Remote observation/publisher adapters require explicit
configuration; their existence does not provision the external services.
Each adapter post resolves the endpoint name again, checks every address in
that answer against the strict HTTPS contract and dials only those addresses.

`channel::ChannelSignatureV1` signs canonical payloads containing a domain,
signer id, epoch, public key, and artifact body. Verifiers check expected identity
metadata before signature verification. Channel byte decoders enforce canonical
input and size limits; replay descriptors allow 4 MiB and authority pins 256 KiB.
Verified wrappers represent the checks performed by their named constructors.
Applications still own anchored mutation storage and external publication.

`verify_solana_binding_and_receipt` verifies carried binding and receipt
signatures and requires the receipt kernel key to match the binding. The shared
verifiers accept Ed25519, P-256, P-384, and hybrid signatures; this helper adds
no algorithm restriction. `prepare_solana_settlement` prepares canonical
instruction bytes and copies the carried signature/key into
`PreparedSolanaSettlement::ed25519_signature` and `chio_public_key`, alongside
the Ed25519 program id. Callers must enforce Ed25519 compatibility for the
native lane; successful preparation alone does not establish it. The helpers
provide no broadcast.

CCIP reconciliation uses a caller-owned `HashSet` for duplicate tracking.
Watchdog helpers assess supplied execution records; they run no scheduler.
Circle and paymaster helpers validate supplied policy without contacting rails.

## Dependencies

`chio-settle-types` supplies the settlement hook, outcome-store, retry and
completion-flow vocabulary and `SettlementError`.
`chio-core`, `chio-credit`, `chio-web3`, and `chio-finding` provide signed
artifacts, canonical serialization, economic continuity, and validation.
`chio-open-market` supplies penalty evidence; `chio-federation` supplies verified
FROST authority. `chio-web3-bindings` and Alloy encode official Solidity ABIs.
`chio-egress-contract`, `reqwest`, and `tokio` support bounded RPC transport;
the finding adapters post through `chio-egress-contract`'s blocking agent.
`secp256k1`, hashes, base58, `secrecy`, and `zeroize` support signing/key handling
and chain encodings. Serde provides strict artifact shapes.

## Verification

`cargo test -p chio-settle --lib` exercises configuration, amount conversion, payment bindings, finding authority, and channel
state transitions. Channel regressions include replay substitutions, canonical
crypto strings, exact terminal batches, and close/release authority changes.
`cargo test -p chio-settle --test channel_schemas` checks schema/wire agreement;
`--test x402_approval_binding` checks token and approval binding behavior.

`tests/runtime_devnet.rs` and `tests/web3_e2e_qualification.rs` launch local
Node/Ganache infrastructure and exercise escrow and recovery flows against the
contract family. They return early when `contracts/node_modules/ethers`,
`contracts/node_modules/ganache`, or working Node imports are unavailable.
Confirm prerequisite execution separately when evaluating those test results.

See the [README](README.md),
[protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract),
and [web3 artifact crate](../chio-web3/README.md).
