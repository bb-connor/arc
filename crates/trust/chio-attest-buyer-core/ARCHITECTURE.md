# Architecture

## Responsibility and boundary

The crate verifies one `ChioProofPackage` against an already validated
`ChioVerifierTrustBundle` and a `ChioVerificationContext`. It owns offline
proof composition checks and their report. It performs no network lookup,
capability issuance, settlement, or persistent replay consumption.

`verify_package` returns an error on rejection. `verify_package_report`
returns a report for either outcome, including checks completed before the
failure. Callers inspecting reports must use `accepted` and `failure`.

## Structure

| Module | Responsibility |
| --- | --- |
| `proof_package`, `claims` | Artifact family, supported claims, scope digest |
| `context` | Audience/challenge/purpose window and BBS nonce derivation |
| `trust_bundle`, `issuer` | Validated peer, vendor, authority, and BBS pins |
| `revocation`, `oracle` | Signed checkpoint and offline revoked-key lookup |
| `disclosure` | Projection, reveal-set policy, subject and nonce checks |
| `report` | Ordered workflow, governance, federation, and BBS verification |
| `input`, `validation`, `error` | Bounded JSON and shared invariant checks |

## Data and control flow

Package parsing uses signed original-input decoding and permits typed
construction before semantic verification. Trust-bundle construction requires
issuers, peers, vendors, action classes, workflow intersections, runtime policy
issuers, lease authorities, and governance authorities. It validates unique
bindings and builds keyed maps for later lookup.

Verification checks supported claims, context, and checkpoint coverage before
workflow signature and externally pinned package hints. It then validates the
workflow intersection hash, vendor cosignatures, step links, lease scope
bindings, trusted leases, governance receipts, and destructive steps.

The verifier hydrates in-memory receipt, lease, and governance stores and
passes them with peer pins and the offline revocation oracle to
`verify_chio_bilateral_invocation`. Every bilateral joint verdict must allow.
Finally, it validates disclosure projection, externally trusted issuer key,
revocation, reveal-set policy, context nonce, and BBS proof.

## Trust and invariants

Package hints must match selected trust entries by key and ladder reference.
The trust bundle may contain unrelated entries; package material cannot add
its own roots. Lease and governance key identifiers must match public-key
fingerprints, with explicit active lifecycle and permitted action classes.
A checkpoint authenticates its envelope signature; choosing its signer and
installing that checkpoint as trusted input remains the caller's boundary.

The effective verification time is the signed checkpoint's issuance time.
The context must be active there and the checkpoint must cover the entire
context window. No wall clock is read by the package verifier. Applications
must prevent selection of stale but internally consistent historical input.

The BBS nonce is the ASCII SHA-256 hex of canonical context fields.
JSON input is bounded to 16 MiB and retains full-width native integers.
Unknown schemas and unsupported claims fail during verification.

## Dependencies

`chio-federation` verifies strict bilateral DSSE and pinned evidence.
`chio-governance` verifies leases and destructive authorization.
`chio-workflow` verifies aggregate/vendor signatures; `chio-selective-disclosure`
provides BBS projection and proof verification. Core types supply canonical
encoding, receipt shapes, hashing, and envelope signature verification.

## Verification

Run `cargo test -p chio-attest-buyer-core` and
`cargo test -p chio-attest-buyer-core --doc`.
`src/tests.rs` covers committed fixtures, forged authority keys, revoked roots,
context mismatch, disclosure policy, and original-input ambiguity.
`cargo bench -p chio-attest-buyer-core --bench buyer_verify` measures the
fixed three-vendor package after checking that its baseline is accepted.

[README](README.md) | [Protocol](../../../spec/PROTOCOL.md#9-trust-control-contract)
