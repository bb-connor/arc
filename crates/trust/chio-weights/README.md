# chio-weights

Model-card schema and attestation helpers for Chio provider binding.
A card declares a SHA-256 weights digest, permitted capability scopes,
banned tools, training-data class, issuer, and validity window. Sigstore
verification and local lineage digest helpers accompany the typed card.

## Usage

Create a fixture card over explicit weights bytes and round-trip canonical JSON:

```rust
use chio_weights::{weights_hash_of, ModelCard, StringSet};
let issued = chrono::DateTime::parse_from_rfc3339("2026-04-30T12:00:00Z")?
    .with_timezone(&chrono::Utc);
let card = ModelCard::new(
    weights_hash_of(b"fixture weights"), StringSet::new(["tool:read"]),
    StringSet::new(["tool:exec"]), "public-internet", "https://example.com/issuer",
    issued, issued + chrono::Duration::days(30),
)?;
let bytes = card.to_canonical_json()?;
assert_eq!(ModelCard::from_canonical_json(&bytes)?, card);
assert!(card.allowed_capability_set.covers(&StringSet::new(["tool:read"])));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Authenticate signed card bytes through `verify_model_card_bundle` with a
trusted verifier, explicit certificate identity expectation, and current time.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; card, bundle, and lineage APIs are available. |
| `smoke` | No | Enables captured cross-provider equivalence test cases. |
| `kani` | No | Selects software SHA-256 and core Kani support; harnesses require `cfg(kani)`. |
| `kani-research` | No | Includes `kani` and opt-in unproved crypto research harnesses. |

## Guarantees

- `ModelCard::new` validates version, lowercase digest, set entries, required
  text, and ordered validity window. Canonical decoding is bounded to 1 MiB.
- `verify_model_card_bundle` delegates bundle authentication, requires the
  card issuer to equal the verified certificate identity, then checks expiry.
- `anchor_model_card` requires supplied bytes to decode to the verified card.
  It emits an unsigned digest anchor; `is_signed` always returns false.
- `verify_model_card_anchor` checks its projection and metadata and rejects
  every imported signed state because no anchor signature verifier is wired.

## Status

Implemented schema, verifier adapter, and local digest anchors. Provider
weights/scope/tool refusal lives in `chio-kernel`'s binding consumer.
Sigstore results retain the shared verifier's transparency limitations.
Unsigned lineage anchors authenticate no registry publisher or deployment.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#41-canonical-json)
- [chio-attest-verify](../chio-attest-verify/README.md)

[License](../../../LICENSE)
