# chio-adversarial-suite

Shared adversarial case envelopes, embedded vectors, and a cross-SDK manifest
for Chio trust-boundary tests. Downstream harnesses use the expected denial
and reason to exercise their own enforcement code.

The crate loads metadata and payloads; executing an attack and checking a
security decision belong to the consuming harness.

## Usage

Load replay cases without reading files or contacting services:

```rust
use chio_adversarial_suite::{bundled_cases_by_class, AttackClass, CaseError, ExpectedVerdict};

fn main() -> Result<(), CaseError> {
    let cases = bundled_cases_by_class(AttackClass::ReplayedNonce)?;
    assert!(!cases.is_empty());
    for case in cases {
        let coverage = case.into_coverage_case()?;
        assert_eq!(coverage.as_case().expected_verdict, ExpectedVerdict::Deny);
    }
    Ok(())
}
```

This validates case eligibility. A harness must separately compare its actual
verdict and reason against the case. `Manifest::from_bundled()` produces the
non-pending manifest with hashes of the embedded JSON bytes.

## Guarantees

- `AdversarialCase::from_slice` parses an envelope with unknown fields rejected
  and calls `validate` for schema version, identifier syntax, nonblank supplied notes,
  and a nonempty object artifact.
- `ExpectedVerdict` accepts only `DENY` during deserialization.
- `into_coverage_case` validates again and rejects `pending: true`.
- `Manifest::from_bundled` rejects path/id drift, skips pending cases, sorts
  entries by id, and pins raw case bytes with SHA-256.

## Status

Implemented test-support library, marked `publish = false`. Class-specific
artifact interpretation and security enforcement remain in downstream tests.
The bundled corpus includes pending cases, so loading all coverage cases can
return `CaseError::PendingCase`. Manifest membership alone establishes no
release or deployment qualification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Arena](../chio-arena/README.md)
- [Case schema](schema/case.schema.json)
- [License](../../../LICENSE)
