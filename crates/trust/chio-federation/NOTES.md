# chio-federation NOTES

## Bilateral verifier profiles

The federation crate keeps two separate verifier profiles:

- `chio.bilateral-signature-slice.v1` binds a local receipt to a DSSE
  signature slice. It is not Chio conformance evidence.
- `chio.bilateral-cosign-invocation.v1` is the strict Chio profile used by
  `verify_chio_bilateral_invocation`.

Strict Chio verification requires `tool_args_hash`, rejects the
`receipt_canonical_json` helper field, requires fresh pinned ladder manifest
references, resolves the receipt body from the configured receipt store, checks
the subject digest, resolves lease and governance references, and fails closed
on unknown action classes.
