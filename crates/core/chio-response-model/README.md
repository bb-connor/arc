# chio-response-model

`chio-response-model` validates active-response plans and durable evidence,
projects lifecycle candidates, and simulates contribution application,
rollback, and expiry. The kernel and quarantine runtime consume this shared
model while retaining admission, persistence, and execution responsibilities.

## Usage

Reject a record whose body cannot decode as a response snapshot:

```rust
use chio_response_model::state::decode_response_record;
use chio_security_types::ports::{
    ActionId, CanonicalBody, Digest32, RecordId, ResponsePlanRecord, TenantId,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let record = ResponsePlanRecord {
        tenant_id: TenantId::new("tenant-1")?,
        action_id: ActionId::new("action-1")?,
        generation: 0,
        state: RecordId::new("planned")?,
        canonical_body: CanonicalBody::new(b"{}".to_vec())?,
        body_hash: Digest32::new([0; 32]),
        due_at_unix_ms: None,
    };
    assert!(decode_response_record(&record).is_err());
    Ok(())
}
```

A body-size wrapper alone cannot establish record integrity. The decoder also
checks canonical encoding, hashes, indexed fields, and snapshot lifecycle.

## Guarantees

- `validate_plan` checks affected-set, contribution, effect-ID, and plan hashes.
- `decode_response_record` compares body-derived values with stored indexes.
- `transition_candidate` checks the expected generation before projection.
- `evaluate_response_simulation` requires dry-run mode and bound snapshot data.
- `rollback_response_simulation` changes caller state only after all ownership
  checks succeed on a cloned candidate.

## Status

This is an implemented pure evidence model with `publish = false`.
It has no stores, effect executors, schedulers, network clients, or clocks.
A successful projection or simulation grants no execution authority and provides
no evidence that a live effect occurred.

## Related

- [Architecture](ARCHITECTURE.md)
- [Trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Protocol substrate](../chio-core-types/README.md)

## License

See the workspace [license](../../../LICENSE).
