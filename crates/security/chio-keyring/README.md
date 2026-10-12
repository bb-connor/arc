# chio-keyring

`chio-keyring` implements authority-key transparency: signed lifecycle events,
operator checkpoints, witness activation, pinned history, and generation-bound
artifact signing. Its SQLite stores retain the history used by Chio authorities.

## Usage

Create and verify a signed genesis envelope offline. Deterministic seeds are
fixture data. This example validates one event without opening a durable log.

```rust
use chio_core_types::{Ed25519Backend, Keypair, SigningBackend};
use chio_keyring::{
    derive_key_id, AuthorityId, BootstrapAuthorization, EventId, KeyLogAuthorizations,
    KeyLogEventBody, KeyLogOperation, LogId, SignedKeyLogEvent, KEY_LOG_EVENT_SCHEMA,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bootstrap = Ed25519Backend::new(Keypair::from_seed(&[1; 32]));
    let authority = Ed25519Backend::new(Keypair::from_seed(&[2; 32]));
    let body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.into(),
        log_id: LogId::new("log-a")?,
        sequence: 0,
        event_id: EventId::new("genesis-a")?,
        previous_event_hash: None,
        authority_id: AuthorityId::new("authority-a")?,
        key_id: derive_key_id(authority.algorithm(), &authority.public_key())?,
        algorithm: authority.algorithm(),
        public_key: authority.public_key(),
        operation: KeyLogOperation::Genesis,
        effective_at: 1_000,
        verify_until: None,
        reason: None,
        issued_at: 1_000,
    };
    let authorizations = KeyLogAuthorizations::bootstrap(
        BootstrapAuthorization::sign(&body, &bootstrap)?,
    );
    let event = SignedKeyLogEvent { body, authorizations };
    let bytes = event.canonical_envelope_bytes()?;
    let decoded = SignedKeyLogEvent::from_canonical_envelope_bytes(&bytes)?;
    decoded.validate_common(0, None, &event.body.log_id, &event.body.authority_id, None)?;
    decoded.verify_genesis(&bootstrap.public_key())?;
    assert_eq!(decoded.envelope_hash()?, event.envelope_hash()?);
    Ok(())
}
```

## Guarantees

- `KeyLogState::replay` validates sequence, predecessor, identities, time
  ordering, and authorizations. Rotation requires witnessed activation.
- `SignedKeyLogEvent` uses canonical, domain-separated signed bytes. Canonical
  envelope decoding is bounded to 1 MiB; signature verification is explicit.
- `SqliteKeyLogStore` binds durable state to configured policy roots, checks
  file custody, and fences its single selector writer. `MultiWorker` is rejected.
- `KeyringSigningRouter` checks the selected identity and signing epoch and
  persists artifact evidence before returning a signature result.
- `WitnessedRotationRuntime` obtains witnessed checkpoints and independent
  auditor confirmation around activation. Recovery also requires configured
  authorization thresholds and proof of possession by the introduced key.

## Status

Implemented replay, transactional SQLite persistence, witness/verifier services,
and authority signing integration. Pure artifact APIs run offline. Service
binaries use Unix sockets; the enterprise composition checks three witnesses,
two auditors, independent keys, storage identities, and fresh signed readiness.
Operators provide protected seed files, durable filesystems, and service custody.
No Cargo features are declared.

## Related

- [Architecture](ARCHITECTURE.md)
- [Serialization and identity](../../../spec/PROTOCOL.md#4-serialization-and-identity)
- [Secure IPC](../chio-secure-ipc/README.md)

[License](../../../LICENSE)
