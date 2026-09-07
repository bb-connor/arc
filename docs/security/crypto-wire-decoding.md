# Cryptographic wire decoding

`chio-core-types` decodes public keys, signatures, signing seeds and hashes from
untrusted text. A successful parse creates transport material, not verified
authority. Callers must still verify signatures, identity, time, scope and policy
at their authorization boundary.

## Finite grammar and allocation bounds

Key and signature wire values have two shapes: a classical value or a hybrid
containing exactly one classical value and one ML-DSA-65 value. The private
`crypto::wire` module represents those shapes separately. Its hybrid parser
cannot recursively parse another hybrid. Unknown algorithm prefixes and
algorithm-set mismatches reject.

Before scanning a key or signature envelope, the parser checks a constant upper
bound derived from the largest supported encoding. Before decoding each hex
component, it checks the component's encoded byte length. Fixed-size values
decode directly into arrays. Only bounded ECDSA signatures use a decoded vector.

| Material | Decoded size |
| --- | --- |
| Signing seed or hash | Exactly 32 bytes |
| Ed25519 public key / signature | Exactly 32 / 64 bytes |
| P-256 public key / signature | Exactly 65 / at most 72 bytes |
| P-384 public key / signature | Exactly 97 / at most 104 bytes |
| ML-DSA-65 public-key / signature half | Exactly 1952 / 3309 bytes |

The ECDSA signature bounds account for a DER sequence containing two positive
integers, each with its maximum scalar width and an optional sign octet. Both
curves fit short-form DER length encoding. Existing in-bound opaque DER inputs
retain their parsing semantics; structure, scalar and curve-point validity are
the cryptographic verifier's responsibility. Rust constructors accepting raw
ECDSA bytes are unchanged and are not wire-size enforcement APIs.

## Serialization compatibility

Canonical output is unchanged. Classical values retain optional lowercase `0x`
input prefixes; hybrid PQ halves remain unprefixed. Hex digits remain
case-insensitive. Hash serialization retains its `0x` prefix. Borrowed and owned
string deserializers both work through one private string visitor shared by
keys, signatures and hashes, without asking the deserializer for a new owned
string. Non-string JSON values reject.

Length validation can change which error is returned for a value that has both
the wrong size and invalid hex. Invalid material does not become accepted.
ECDSA wire values exceeding the largest valid DER encoding now reject during
parsing, even though older code retained their bytes until verification.

These bounds cover work performed by the crypto and hash parsers, not an
enclosing transport buffer or deserializer's escape-processing scratch buffer.
Endpoints must retain body-size and read-time limits. This change does not
establish an end-to-end memory bound for arbitrary JSON documents.

## Regression evidence

`tests/crypto_wire_bounds.rs` isolates deeply nested key and signature inputs in
child processes, both through direct parsing and through JSON deserialization.
Before the fix, all four controls terminated with a stack overflow. Separate
controls reproduced oversized ECDSA acceptance, decode-before-length checking,
and unnecessary owned-string requests. The corrected parsers return errors
without descending into nested hybrids or decoding oversized hex.

Positive controls cover maximal DER transport encodings, canonical round trips,
borrowed/owned strings and real signatures. The `fips` and `pq` feature profiles
exercise P-256, P-384 and all three supported classical plus ML-DSA-65 families.
Changed messages and the existing hybrid bit-flip tests must still reject.
Property tests exercise accepted and rejected algorithm-prefixed hex strings.

The existing `chio-tee-fips` workflow executes the feature-enabled wire tests
and checks their exact listed and executed inventory. The child-process tests
also require one executed, successful regression, not just a zero exit status.
The same job builds `no_std` WASM with and without `pq`. The PQ build exposed
missing explicit `alloc` imports that default `std` builds had masked; those
imports are now present. A cross-target build is not a browser execution test.

The Cargo feature named `fips` selects the ECDSA backend in this crate. Enabling
it alone is not evidence of a validated FIPS module or a qualified deployment.
See the [launch ledger](launch-plan.md) for executed feature profiles and the
remaining full-runtime qualification gates.
