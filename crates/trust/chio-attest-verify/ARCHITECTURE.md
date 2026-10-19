# Architecture

## Responsibility and boundary

`AttestVerifier` is Chio's common artifact verification trait.
`SigstoreVerifier` implements detached-file, detached-byte, and bundle paths.
`TenantPolicyResolver` maps tenant ids to pinned certificate expectations.
`QuoteVerifier` defines the separate kernel-key/receipt-root binding interface.

Verification errors remain typed through `AttestError`. Consumers decide
whether the returned evidence meets their local admission policy, including
whether missing independent transparency verification is acceptable.

## Structure

| Module | Responsibility |
| --- | --- |
| `sigstore/core` | Embedded Fulcio roots and synchronous trait implementation |
| `sigstore/identity`, `validators`, `parse` | SAN/issuer, chain, signature, certificate parsing |
| `sigstore/bundle_verify`, `material`, `policy` | Async bridge, bundle metadata, issuer policy |
| `policy`, `policy_loader` | Tenant TOML validation, canonical signing, freshness |
| `quote` | TEE families, TCB status, 64-byte report-data binding |
| `tdx`, `sev_snp`, `nitro`, `tee_signature` | Optional quote parsing, collateral checks, ECDSA |
| Kani modules | Direct report-data harnesses and separate quote outcome models |

## Data and control flow

Construction parses embedded `trusted_root.json`, retains Fulcio certificates,
and creates a current-thread Tokio runtime. `build.rs` checks root-file
presence and sets rebuild triggers. It performs no TUF authenticity check.

Detached verification parses the leaf, validates its chain against embedded
Fulcio roots, matches identity, checks current validity, and verifies the
signature.
Bundle input first passes a bounded external JSON decoder, then the Sigstore
bundle verifier, followed by Chio's anchored SAN and exact issuer checks.
The async bridge uses a helper runtime thread when called inside Tokio.

Policy parsing checks size, unknown fields, bounded regex/issuer collections,
and required text. `load_signed` additionally authenticates canonical JSON
excluding the signature and enforces future-time and age checks.
`StaticTenantPolicyMap::from_verified` trusts its caller's prior signature
verification; it checks structural validity, duplicate tenants, and one issuer.

## Trust and invariants

Sigstore trust roots are embedded inputs. All current result paths report
`rekor_inclusion_verified = false`; log index and integrated time are metadata.
A successful bundle result does not claim independent Merkle/SET verification.
The default policy age horizon is 90 days, with caller-supplied current time.

`expect_report_data` hashes the public key's canonical hex bytes followed by
the 32-byte receipt root, then zero-pads to 64 bytes. Quote verifiers compare
all 64 bytes. SEV-SNP adds a 48-byte launch digest pin; Nitro adds PCR0 and a
five-minute timestamp skew check. TDX checks header vendor/key type and TCB
recovery id, without an explicit expected workload measurement.

Quote collateral is caller-supplied: chain helpers require nonempty links,
at least two entries, a distinct leaf, and root-byte equality. They do not
verify certificate-link signatures. TCB status and validity windows are
supplied values. Raw SEC1 fixture leaf keys are accepted by ECDSA helpers.
These checks support deterministic corpora; they do not establish vendor
endorsement authenticity or real hardware attestation by themselves.

## Dependencies

Sigstore supplies bundle and Fulcio materials; WebPKI handles the detached
certificate path. Serde/TOML and regex enforce tenant policy structure.
Optional P-256/P-384 and COSE dependencies implement quote signature checks.
Core types supply strict JSON, canonical encoding, public keys, and hashing.

## Verification

Run `cargo test -p chio-attest-verify` and
`cargo test -p chio-attest-verify --features tee-quotes`.
Policy tests exercise parsing, signer failure, age, and tenant resolution.
Quote integration tests hash-pin synthetic corpora and exercise malformed,
measurement, binding, signature, and root-rotation failures.
PQ migration tests require `--features pq`. Kani quote models cover their
local outcome logic; runtime quote implementations are exercised by tests.

[README](README.md) | [Serialization](../../../spec/PROTOCOL.md#41-canonical-json)
