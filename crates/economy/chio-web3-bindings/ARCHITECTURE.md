# chio-web3-bindings architecture

## Responsibility and boundary

The crate owns compile-time ABI bindings and embedded contract artifacts for
five Chio interfaces. It exposes call/event data types for root and identity
registries, escrow, bond vault, and price resolver. Consumers own providers,
contract addresses, account authorization, and deployment trust.

`ChioMerkleProof` is a shared Rust representation of Solidity proof fields.
Its conversion implementations bridge the independently generated root-registry,
escrow, and bond-vault proof types. This crate does not decide whether a proof
is valid or whether a root is authorized for a particular operation.

## Structure

`src/lib.rs` declares `interfaces`, re-exports the five generated interfaces and
`ChioMerkleProof`, and embeds JSON with `include_str!`. Entire-crate `web3`
gating removes all public items when the feature is disabled.

`src/interfaces.rs` contains five private binding modules. Each invokes
`alloy::sol!` on its corresponding `artifacts/interfaces/IChio*.json` path,
resolved with `CARGO_MANIFEST_DIR`. Interface names are then re-exported.
The generated Solidity `ChioMerkle::Proof` structs remain distinct Rust types.

| Packaged directory | Contents |
| --- | --- |
| `artifacts/interfaces` | Compiled interface ABI inputs, including support interfaces. |
| `artifacts` | Five Chio implementation artifacts with ABI and bytecode fields. |
| `artifacts/lib`, `artifacts/mocks` | Merkle library and contract-test support artifacts. |
| `deployments` | Embedded local-devnet deployment fixture. |
| `reports` | Embedded local-devnet qualification fixture. |

Only the five Chio interface and implementation artifacts, plus the two devnet
fixtures, have string constants exported by the crate root. Supporting files
remain package data rather than separately exported Rust constants.

## Data and control flow

A build reads interface JSON through the `sol!` macro and generates callable
Solidity data types. A consumer constructs a call, uses Alloy's `SolCall` to
encode it, and sends those bytes through its own transport. Return/event decoding
uses the corresponding generated types; this crate performs no dispatch.

Proof conversion copies `audit_path`, `leaf_index`, and `tree_size` into the
Solidity field names. Borrowed conversions clone the audit path. Owned
conversions delegate to the borrowed form and therefore also clone that vector.
There is no validation, hashing, index narrowing, or signature operation in
these conversions.

## Trust and invariants

Bundled artifacts determine ABI shape at compilation. The public API therefore
tracks the packaged interface artifacts. Updating an ABI requires rebuilding
and reviewing generated signature parity and implementation coverage.

Artifact unit tests require names and nonempty ABIs, implementation creation
and runtime bytecode, and correct Keccak bytecode hashes. Interface artifacts
must contain empty bytecode/hash fields. These are test-enforced package
conditions; exposing a string constant does not run validation automatically.

The devnet manifest/report constants are fixed test fixtures. Their presence
cannot authorize a deployment or prove a live address has matching code.
An application must independently validate chain identity, runtime codehash,
contract configuration, signer standing, and finality for its operation.
ABI encoding supplies the wire shape; receipt truth and trust checks live in
the consuming runtime and artifact verifiers.

## Dependencies

Optional `alloy` enables JSON ABI/`sol!` support and the primitive types used by
proof fields. Optional `serde_json` supports artifact parsing in tests.
`web3` enables both dependencies, and `default` enables `web3`.
Development dependencies `chio-core`, `chio-link`, and `chio-web3` support
cross-crate parity with standards artifact types and oracle runtime constants.
No transport or signing dependency is configured by this crate.

## Verification

Use `cargo test -p chio-web3-bindings` with default features.
Unit tests parse all exported artifacts, reject empty implementation bytecode,
recompute creation/runtime hashes, and check fixture IDs.
`tests/parity.rs` rejects duplicate ABI entries, compares generated function
and event signature sets/selectors, and checks each interface is a subset of
its implementation. It also checks standards package/deployment references
and oracle authority constants against sibling Rust types.
These checks use packaged files; querying current chain code requires a
separate deployment verification run.

[README](README.md) · [Solidity package](../../../contracts/README.md)
