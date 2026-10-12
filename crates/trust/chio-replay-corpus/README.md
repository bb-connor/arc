# chio-replay-corpus

Normalizes redacted TEE captures into deterministic replay fixtures. The crate
provides canonical invocation deduplication, current-default re-redaction,
fixture writing, and signed blessing audit entries for Chio replay tooling.

## Usage

Normalize payloads in memory and derive a stable invocation key. No fixture or
audit file is written by this example.

```rust
use chio_replay_corpus::{invocation_hash, reredact_default};
use serde_json::json;

let left = invocation_hash(&json!({"tool":"read", "args":{"limit":10}}))?;
let right = invocation_hash(&json!({"args":{"limit":10}, "tool":"read"}))?;
assert_eq!(left, right);

let redacted = reredact_default(b"contact alice@example.com")?;
let text = String::from_utf8(redacted.bytes)?;
assert!(text.contains("[REDACTED-EMAIL]"));
assert!(!text.contains("alice@example.com"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

- `dedupe_last_wins` hashes RFC 8785 invocation bytes and retains the final
  occurrence of each key, ordered by those final input positions.
- `reredact_default` uses `RedactPass::with_default` and fail-closed redaction.
  `ReredactedPayload` retains bytes, pass id, and matches while omitting timing.
- `write_fixture` rejects empty captures and unexpected destination entries,
  then re-redacts canonical invocation bytes before serializing replay records.
- `TeeBlessAuditBody::validate` checks required fields, capture counts, and the
  root encoding before `TeeBlessAuditEntry::sign` signs the canonical body.

## Status

Implemented replay-fixture tooling. Fixture records are stripped observations
with a deterministic replay root. Fixture generation does not verify TEE
attestation, capture signatures, kernel receipts, or runtime admission.
`write_fixture` stages and renames three files individually; directory-wide
atomic replacement is outside its guarantee. Callers own blessing authorization
and the audit-log destination. The crate declares no Cargo features and is
unpublished (`publish = false`).

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [TEE capture support](../chio-tee/README.md)
- [TEE frame format](../chio-tee-frame/README.md)

[License](../../../LICENSE)
