//! Pin the actual physical producer and its historical data-only reader.
use super::*;
use chio_core::canonical::UntrustedJsonError;
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionOperationError, AdmissionOperationStoreError,
    NativeSecurityDispatchLedgerRecordV1, NativeSecurityDispatchRequestBindingV1,
};
use std::error::Error;

pub(super) fn verify(
    ledger: &NativeSecurityDispatchLedgerRecordV1,
    record: &serde_json::Value,
    request: &chio_kernel::ToolCallRequest,
) -> TestResult {
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(record)?,
        ledger.canonical_record
    );
    let mut fields: Vec<_> = record
        .as_object()
        .ok_or("ledger object")?
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "approval",
            "context",
            "decision_at",
            "dpop",
            "egress_acquisition",
            "egress_commitment",
            "grant_digest",
            "grant_index",
            "join_digest",
            "lease",
            "live_request_digest",
            "observed_at",
            "operation",
            "original_dispatch_commitment_id",
            "policy",
            "runtime",
            "schema",
        ]
    );
    let context: chio_kernel::SecurityInvocationContext =
        serde_json::from_value(record["context"].clone())?;
    let expected = NativeSecurityDispatchRequestBindingV1::from_live_request(request, &context)?;
    let retained = NativeSecurityDispatchRequestBindingV1::from_ledger(ledger, &context)?
        .ok_or("v2 original request binding")?;
    assert!(retained == expected);
    assert_eq!(
        record["original_dispatch_commitment_id"],
        serde_json::to_value(expected.dispatch_commitment_id())?
    );
    assert_eq!(
        record["live_request_digest"],
        chio_core::sha256_hex(&chio_core::canonical::canonical_json_bytes(request)?)
    );

    // Historical v1 has no original full-request commitment. Reading its
    // structure must preserve that absence, never synthesize fresh authority.
    let mut legacy = record.clone();
    legacy["schema"] = serde_json::json!("chio.native-dispatch-preparation-ledger.v1");
    legacy
        .as_object_mut()
        .ok_or("ledger object")?
        .remove("original_dispatch_commitment_id");
    let legacy_record = with_bytes(ledger, &legacy)?;
    assert!(
        NativeSecurityDispatchRequestBindingV1::from_ledger(&legacy_record, &context)?.is_none()
    );
    legacy["original_dispatch_commitment_id"] = record["original_dispatch_commitment_id"].clone();
    assert!(matches!(
        NativeSecurityDispatchRequestBindingV1::from_ledger(&with_bytes(ledger, &legacy)?, &context),
        Err(AdmissionOperationStoreError::Invariant(detail)) if detail == "original native ledger schema is invalid"
    ));

    let mut missing = record.clone();
    missing
        .as_object_mut()
        .ok_or("ledger object")?
        .remove("original_dispatch_commitment_id");
    match NativeSecurityDispatchRequestBindingV1::from_ledger(
        &with_bytes(ledger, &missing)?,
        &context,
    ) {
        Err(AdmissionOperationStoreError::Operation(AdmissionOperationError::UntrustedInput(
            shared,
        ))) => {
            assert_eq!(
                shared.code(),
                "urn:chio:error:attest:signed-json-invalid-shape"
            );
            match shared
                .source()
                .and_then(|cause| cause.downcast_ref::<UntrustedJsonError>())
            {
                Some(UntrustedJsonError::Decode(error)) => {
                    assert_eq!(error.classify(), serde_json::error::Category::Data);
                    assert_eq!(
                        error.to_string(),
                        "invalid type: null, expected a bounded canonical identifier"
                    );
                }
                _ => panic!("missing v2 commitment must preserve its typed Serde data cause"),
            }
        }
        Err(error) => panic!("missing v2 commitment changed error owner: {error:?}"),
        Ok(_) => panic!("v2 ledger accepted a missing original commitment"),
    }
    Ok(())
}

fn with_bytes(
    ledger: &NativeSecurityDispatchLedgerRecordV1,
    value: &serde_json::Value,
) -> Result<NativeSecurityDispatchLedgerRecordV1, Box<dyn std::error::Error>> {
    let canonical_record = chio_core::canonical::canonical_json_bytes(value)?;
    Ok(NativeSecurityDispatchLedgerRecordV1 {
        operation_id: ledger.operation_id.clone(),
        record_digest: AdmissionDigest::try_new(
            "ledger",
            chio_core::sha256_hex(&canonical_record),
        )?,
        canonical_record,
    })
}
