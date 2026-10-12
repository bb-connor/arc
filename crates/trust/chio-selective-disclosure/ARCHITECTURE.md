# chio-selective-disclosure architecture

## Responsibility and boundary

The crate owns projections for `ChioReceiptBody`, `WorkflowReceiptBody`, and
`StepRecord`, optional BBS signatures and proof packages, manifest checks, and
transparency path checks. It re-exports disclosure-lineage verification types.
Default builds expose representation and consistency helpers; `bbs` enables
cryptographic key, signing, proof, and context-verification entry points.

A valid BBS proof authenticates a selected message set under a registered key.
A consumer separately establishes issuer authority, manifest policy, current
status, expected nonce, and trust in any transparency root.

## Structure

| Source | Responsibility |
| --- | --- |
| `src/lib.rs` | Projection tables, carriers, BBS operations, manifest and inclusion checks. |
| `src/encoding.rs` | Canonical hashes, strict hex, scalar and optional encodings. |
| `src/projection_manifest.rs` | Manifest slots and hidden-predicate descriptors. |
| `src/crypto_context/types.rs` | Context, key/status state, errors, privacy report types. |
| `src/crypto_context/policy.rs` | Feature-gated policy and freshness comparisons. |
| `src/crypto_context.rs` | BBS verification followed by context report generation. |

## Data and control flow

Projection functions create an ordered message vector and a SHA-256 digest of
the canonical source object. Strings, booleans, little-endian integers, decoded
hashes, and canonical structured hashes use distinct encoding tags.
Manifest generation assigns message and sensitivity classes and hides
wholesale-only fields plus exact duration.

BBS signing domain-separates each message's index, field, encoding, and bytes.
The proof header binds projection version, subject digest, issuer fingerprint,
and suite. Derivation first verifies the full signature and issuer-key match,
then generates a proof over the selected indices and supplied nonce.

Verification looks up the fingerprint in `InMemoryIssuerRegistry`, checks the
registered key, derives message count from proof size, validates unique indices
and disclosed-message ordering, and invokes Affinidi proof verification.
The returned `VerifiedDisclosure` contains the authenticated disclosed messages.

## Trust and invariants

The registry accepts caller-inserted fingerprint/key pairs. It provides no
persistent trust registry or key lifecycle checks.
Bare proof verification uses the nonce carried by the proof. The context wrapper
adds comparison to caller-supplied nonce and replay status; it does not keep a
nonce store or authenticate holder possession itself.

`verify_selective_disclosure_with_context` checks policy against supplied key
windows, epochs, revocation snapshot age, audience, holder state, transparency
state, and presentation time. Policy failure returns a rejected report after
successful proof verification. Reports are initially unsigned.
The wrapper does not enforce the profile's revealed-field allowlist or count
budget; bundle and manifest checks provide separate disclosure constraints.

`sign_chio_receipt_with_bbs` checks WYSIWYS through `ReceiptSigningHandle` before
signing a projection and embedding its material in the authoritative receipt.
`receipt_signed_projection` verifies that receipt signature and projection
binding; full BBS signature verification remains a separate operation.

Manifest verification enforces slot shape and exact disclosed coverage without
executing BBS verification. Transparency verification reconstructs a path to
the supplied root; it does not authenticate a checkpoint signer or root origin.

Proof packages retain subject digest, issuer key/fingerprint, message count,
nonce, and disclosed fields. Repeated presentations can expose correlation and
inference through these values. There is no general amount range-proof engine;
hidden-predicate descriptors alone establish no predicate proof.

## Dependencies

`affinidi-bbs` provides the optional BLS12-381 SHA-256 BBS suite.
`chio-core-types` supplies receipt types and canonicalization; `chio-workflow`
supplies workflow and step inputs. `chio-disclosure-lineage` handles signed graph
and ledger consistency. Serde, `sha2`, and `hex` encode and hash proof material.

## Verification

Run `cargo test -p chio-selective-disclosure` for manifest, duration privacy,
transparency-path, and re-exported lineage cases.
Run `cargo test -p chio-selective-disclosure --features bbs` for signature and
proof tampering, issuer/nonce binding, receipt WYSIWYS, and context-policy cases.
The offline `chio_fixture` example requires `bbs` and writes caller-selected
fixture output. The library has `test = false`; integration targets carry tests.
