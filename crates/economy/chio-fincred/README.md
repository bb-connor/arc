# chio-fincred

`chio-fincred` defines shared financial credential wire types. Credit issuers
and credential verifiers use the same family identifiers, subject claims,
source disclosures, checkpoints, and completeness attestations. The crate
keeps those contracts independent of a database or credential transport.

## Usage

Construct a settlement-reliability subject and round-trip its tagged JSON.
This encodes claims; the example does not authenticate their source.

```rust
use chio_fincred::{
    FinancialCredentialFamilyV1, FinancialCredentialSubjectV1,
    SettlementReliabilityCredentialSubjectV1,
};

fn main() -> Result<(), serde_json::Error> {
    let subject = FinancialCredentialSubjectV1::SettlementReliability(
        SettlementReliabilityCredentialSubjectV1 {
            id: "did:chio:operator".into(),
            on_time_count: 9,
            obligation_count: 10,
            on_time_ratio_bps: 9000,
        },
    );
    assert_eq!(subject.family(), FinancialCredentialFamilyV1::SettlementReliability);
    let encoded = serde_json::to_string(&subject)?;
    let decoded: FinancialCredentialSubjectV1 = serde_json::from_str(&encoded)?;
    assert_eq!(decoded, subject);
    Ok(())
}
```

`serde_json` is available to this crate's tests. Consumers add their chosen
serialization library alongside `chio-fincred`.

## Guarantees

- `FinancialCredentialFamilyV1::schema`, `label`, and `credential_type` return
  fixed identifiers for the five supported families. `from_schema` returns
  `None` for an unrecognized schema.
- `FinancialCredentialSubjectV1::family` and `id` dispatch to the matching
  subject variant. Serde encodes it with `family` and `claims` fields.
- Contract structs use `deny_unknown_fields` during Serde decoding. Typed
  decoding does not check signatures, time windows, ratios, or digest contents.

## Status

This crate implements types and identifier helpers. Signed source aliases use
`SignedExportEnvelope`; financial source validation and claim projection live
in `chio-credit`, while credential consumption lives in `chio-credentials`.
Callers must authenticate evidence and apply policy before granting authority.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol serialization](../../../spec/PROTOCOL.md#41-canonical-json)
- [Credit projections](../chio-credit/README.md)
- [Credential verification](../../trust/chio-credentials/README.md)

License: [Apache-2.0](../../../LICENSE).
