# Pinned WebAuthn fixture corpus

This is a JSON-descriptor corpus that pins the failure-mode taxonomy the
verifier must enforce (replayed challenge, mismatched origin, expired
challenge, malformed CBOR, plus four positive shapes). The descriptors
carry the intended verifier verdict and the registry URN every negative
case must surface.

A later revision will replace each descriptor with a byte-pinned WebAuthn
assertion captured from a real authenticator. The descriptor schema is
forward compatible: it can add an `assertion_b64` field carrying the wire
bytes and a `relying_party_id` / `origin` pair the verifier was configured
with at capture time.

## Schema

Each `*.json` file under `positive/` and `negative/` carries:

```jsonc
{
  "id": "human-readable identifier",
  "kind": "positive" | "negative",
  // Failure category (negative only). Maps 1:1 to a urn:chio:error:custody:*
  // row in spec/errors/registry.yaml.
  "failure_mode": "replayed-challenge" | "mismatched-origin"
                | "expired-challenge" | "malformed-cbor",
  // Stable URN the verifier MUST surface for this fixture.
  "expected_urn": "urn:chio:error:custody:*"
}
```

TODO(security): a later revision wires a real `webauthn-rs`
`start_passkey_authentication` state plus byte-pinned `PublicKeyCredential`
JSON so the verifier actually exercises the cryptographic path. The current
corpus only proves the corpus directory shape and the verdict taxonomy.
