# Architecture

## Responsibility and boundary

The crate owns `ModelCard`, sorted string sets, a generic Sigstore verifier
adapter, and model-card lineage digest artifacts. It supplies data and checks
used by provider binding. The kernel consumer owns loaded-weights comparison,
requested-scope containment, and banned-tool refusal.

`VerifiedModelCard` pairs a card with attestation metadata. Its fields are
public; constructing that type directly does not invoke authentication.
Use `verify_model_card_bundle` when accepting external signed cards.

## Structure

| Module | Responsibility |
| --- | --- |
| `card` | Versioned schema, sorted sets, canonical codec, weights hashing |
| `bundle` | Generic `AttestVerifier` adapter and issuer/expiry checks |
| `lineage` | Canonical projection, unsigned anchor, imported-anchor checks |
| `error` | Schema, expiry, bundle, binding errors and stable error URNs |
| Kani modules | Public helper harnesses and separate crypto research |

The crate has a `dump_minimal_card` example and golden canonical-card bytes.
Integration tests cover canonical JSON, bundle adaptation, anchor verification,
seeded hash binding, and feature-gated captured provider equivalence.

## Data and control flow

`ModelCard::new` validates the completed card. `StringSet::new` deduplicates
and sorts; deserialization rejects duplicate, blank, or padded entries.
`from_canonical_json` bounds input to 1 MiB, requires canonical typed bytes,
and reruns structural validation. `to_canonical_json` only encodes the value;
callers mutating public fields must validate it before using it as trusted data.

`verify_model_card_bundle` passes the original card bytes, bundle, and identity
expectation to the supplied verifier. It then decodes canonical card bytes,
requires `card.issuer` to equal the verified certificate SAN identity, and
checks `now < expires_at`. It returns card and attestation together.

`anchor_model_card` first compares decoded bytes with `verified.card`, hashes
a canonical projection containing card digest and selected attestation fields,
and lifts card and attestation metadata into the anchor. A signer hint records
`UnsignedSignerStubbed`; its absence records `UnsignedSoftDepAbsent`.
Neither path produces a signature.

## Trust and invariants

Cards require version `1`, lowercase 64-character weights digest, unpadded
required text/set entries, and `expires_at >= issued_at`. Empty scope or banned
tool sets are allowed. `require_live` checks expiry only; it does not reject
future issuance time. Bundle signature behavior depends on the injected
`AttestVerifier`; tests use fake verifiers to isolate adapter behavior.

The standard Sigstore implementation reports independent Rekor inclusion as
false. The adapter preserves that metadata. Certificate identity and card
issuer must agree exactly after authentication.

`verify_model_card_anchor` recomputes the digest and compares card/attestation
metadata, then rejects all `SigningState::Signed` imports. Successful unsigned
verification establishes consistency with the caller's supplied inputs.
It does not reauthenticate the bundle, check current card liveness, publish
to a registry, or verify publisher identity. `is_signed` always returns false.

The kernel's `weights_binding` helpers compare a supplied loaded-weights
digest and enforce requested scope/tool restrictions. Their loaded-hash wrapper
rejects an unavailable provider digest. They do not rehash bytes, validate the
card, or check expiry; upstream callers must supply those checks.

## Dependencies

Core types supply canonical JSON, strict original-input handling, and hashes.
`chio-attest-verify` supplies the shared verification trait and metadata.
`chio-lineage` supplies frontier digest and explicit signing-state types.
Chrono handles validity times; Serde, SHA-256, and hex support wire projection.
Provider conformance is a development dependency for captured fixture tests.

## Verification

Run `cargo test -p chio-weights` and
`cargo test -p chio-weights --features smoke`.
Canonical tests compare exact golden bytes. Bundle tests check pass-through,
issuer agreement, malformed card rejection, and expiry with fake verifiers.
Lineage tests check digest tampering and rejection of unverified signed state.
Smoke cases compare captured fixture verdicts; they do not contact providers.
Kani scope is determined by each direct-helper or model harness.

[README](README.md) | [Serialization](../../../spec/PROTOCOL.md#41-canonical-json)
