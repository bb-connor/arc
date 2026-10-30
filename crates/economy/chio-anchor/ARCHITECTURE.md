# chio-anchor architecture

## Responsibility and boundary

The crate owns checkpoint-proof projection, signed checkpoint-ID batches,
publication preparation, EVM RPC helpers, and witness-policy evaluation.
`AnchorServiceConfig` describes targets; it creates no scheduler or durable
store. Public lane APIs are re-exported from private modules at the root.
`metrics` is public, and `fuzz` is public under its feature.

Kernel checkpoints and receipt exports arrive from `chio-kernel`.
Applications provide authorized signing keys, RPC policy, publication ownership,
and external observations. Durable receipt storage and kernel-signed checkpoint
issuance are prerequisites when the surrounding runtime claims anchor readiness.

## Structure

| Module | Responsibility |
| --- | --- |
| `lib` | Converts kernel statements and inclusion proofs; projects evidence exports. |
| `batch` | Builds/signs ID Merkle trees and verifies local batch structure. |
| `witness` | Stable batch hash, witness lifecycle, async clients, verifier cache policy. |
| `witness/rekor` | Rekor entry parsing, P-256 signed-entry timestamps, optional Merkle paths. |
| `witness/ots` | Calendar submission and advisory OTS receipts. |
| `evm` | Splits preparation, RPC, publication confirmation, validation, hashing, and records. |
| `bitcoin`, `solana` | Super-root/OTS linkage and canonical memo-record checks. |
| `bundle`, `discovery` | Lane composition, publication records, service/freshness policy. |
| `functions`, `automation` | Functions request assessment and publication-job assessment. |
| `ops`, `metrics` | Emergency controls, lane/indexer reports, counters and latency export. |

## Data and control flow

`build_anchor_inclusion_proof` selects the proof version from the checkpoint
schema, projects kernel fields, and invokes core anchor validation and signature
verification. The evidence-export variant finds the requested receipt and its
checkpoint material; uncheckpointed or missing records fail.

`prepare_root_publication` checks target addresses, binding purpose/chain scope,
and operator-address agreement before encoding `publishRoot` calldata.
The caller verifies signatures and current validity before preparation, then
invokes publication readiness checks. `publish_root` estimates gas and uses
`eth_sendTransaction`; the provider must authorize the publisher account.
It does not invoke the readiness preflight itself.

`confirm_root_publication` checks receipt success, transaction/target/event
identity, checkpoint fields, and registry state at the publication block.
It uses an EIP-1898 canonical block-hash call, with a narrowly matched Ganache
compatibility fallback to block number. RPC results remain observations from
the configured endpoint; this helper supplies no finality threshold.

## Trust and invariants

`build_anchor_batch` canonicalizes each ID, constructs ordered inclusions,
overwrites the descriptor root, signs the body, and starts in `Pending`.
`verify_anchor_batch` reconstructs the tree and checks leaf hashes, inclusion
order, witness-root equality, and the embedded-key signature. ID membership
alone supplies no verification of the underlying checkpoint objects.

The sync witness-policy wrapper rejects `require_public_witness=true` before
structural checks. The async wrapper requires live witness validation for
`Witnessed`; `Stale` requires a verifier-owned cache time for the stable
`batch_body_hash`, within policy age and never in the verifier's future.
The stable hash excludes lane-assigned IDs and witness lifecycle timestamps.

Rekor checks body/UUID binding and a signed-entry timestamp under pinned keys.
When present, an inclusion path is recomputed against its carried root and
SET-bound leaf/index. Missing inclusion paths are accepted; no separately
pinned signed tree head is required or authenticated by that helper.
OTS witness verification
fails closed because marker-only timestamp material cannot establish trusted
Bitcoin publication. Witness clients currently use direct reqwest clients;
EVM RPC helpers separately enforce `HttpEgressContract`.

`verify_proof_bundle` checks local signatures and declared lane material.
V2 bundles require a primary chain record. Bitcoin linkage checks digest and
attestation-height markers, and Solana checks canonical memo/root/sequence;
neither path independently fetches trusted chain state. Discovery-aware checks
also enforce identity agreement, lane inventory, and supplied freshness state.

## Dependencies

`chio-core` supplies canonical signing, Merkle hashing, receipts, and web3 types;
`chio-kernel` supplies checkpoint/export records. `chio-web3-bindings` and Alloy
encode/decode EVM calls. `reqwest` provides HTTP transport, `opentimestamps`
parses OTS documents, and `p256` authenticates Rekor signed-entry timestamps.
`chio-egress-contract` constrains EVM RPC dispatch; `chio-metrics-spec` provides
metric names and support. `arbitrary` is enabled only by `fuzz`.

## Verification

Use `cargo test -p chio-anchor --features web3`; the default build compiles an
empty crate.
`batch` tests cover round trips and forged roots; `witness` tests cover pending,
self-asserted witnessed states, stale cache binding, and policy routing.
Rekor tests cover signed-entry tampering and malformed inclusion paths.
EVM tests use loopback JSON-RPC servers and may skip when loopback binding is
unavailable. Integration tests cover checkpoint round trips, discovery, Functions
response binding, emergency operations, OTS continuity, and memo validation.
Kani harnesses require the Kani toolchain; ordinary feature activation does
not execute a proof campaign.

[README](README.md) · [Protocol checkpoints](../../../spec/PROTOCOL.md#65-checkpoints)
