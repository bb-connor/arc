# Registered work wire vectors

`manifest.json` lists 57 exact byte inputs and their parser outcomes. Rust's
`shared_malformed_vectors_match_the_registered_rust_parser` and Python's
`funded_wire.py --vectors` consume the same files. Four positive inputs represent
the registered agreement v2, submission v1, dependency v1 and decision v2.

The positive bytes were emitted by the Rust unit fixture with generated signing
keys, a retained native outcome and the actual Finding verifier. They are parser
fixtures, not externally pinned authorities or chain proofs. In particular the
decision's claim transaction/block are unit inputs, and the dependency references
separately generated fixture agreements. Production signature, party-role,
original-request, custody and observed-chain checks remain mandatory. Historical
Finding timestamps are intentionally retained; parsing does not establish
current admission eligibility. No fixture contains a private key or capability.

Negative vectors retain the exact malformed raw bytes. They cover ordinary and
escaped duplicate keys, unknown fields and versions, null versus absent, unsafe
numbers, alternate hex/decimal encodings, missing or reordered facet floors,
oversized UTF-8 identifiers, aliased dependency authorities, incomplete facet
reports and blank reasons. Signatures need not be valid to test raw parsing;
separate Rust tests re-sign authority substitutions to prove cryptography alone
cannot bypass the original context or facet requirements.

Reproduce the two parser runs:

```sh
CARGO_TARGET_DIR=target cargo test --locked --manifest-path examples/federated-work/Cargo.toml shared_malformed_vectors
python examples/federated-work/funded_wire.py --vectors examples/federated-work/fixtures/registered-work/manifest.json
```

Use the existing Python environment installed from the hashed buyer requirements.
The Python checker independently parses canonical JSON and implements only the
closed schema vocabulary used by these six local schemas. Unknown vocabulary and
non-local references fail closed; it performs no network resolution.
