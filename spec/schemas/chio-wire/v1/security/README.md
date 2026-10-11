# Chio Wire Schemas v1: security/

This subtree contains the closed JSON Schema contract for Chio's enterprise
security wire artifacts. Every object schema rejects unknown fields. Signed
artifact families publish the exact body and envelope shapes independently so
implementations can canonicalize the body before verifying the envelope.

`required-schema-inventory.json` is a closed inventory of every schema in this
directory. `exported-signed-artifact-schema-map.json` maps the exported Rust
signed artifact types to their body and envelope schemas. The schema registry
gate recursively scans every Rust file under the declared source roots for
public `Signed*`, `*Signature`, and `*Proof` structs. Each discovery must have a
schema mapping or a typed exclusion with a specific reason. The gate also
rejects a missing schema, an unregistered schema, or a discriminator that has
drifted from its Rust constant.

Canonical positive vectors and cryptographic-field mutations for these mapped
artifacts live in `tests/bindings/vectors/security/signed-wire/`.
