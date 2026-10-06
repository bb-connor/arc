//! Compare actual authenticated delivery with the independently retained capture.
use super::*;

pub(super) fn verify(
    raw: &chio_kernel::tool_outcome::RawInvocationOutcomeV1,
    operation: &chio_kernel::admission_operation::AdmissionOperationV1,
    ledger: &chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1,
) -> TestResult {
    let persisted = raw.to_persisted();
    let value: serde_json::Value = serde_json::from_slice(&ledger.canonical_record)?;
    let original = persisted
        .original_security_dispatch_binding
        .as_ref()
        .ok_or("original native dispatch binding")?;
    assert_eq!(
        value["schema"],
        chio_kernel::admission_operation::NATIVE_DISPATCH_LEDGER_SCHEMA
    );
    assert_eq!(
        original.dispatch_commitment_id().as_str(),
        value["original_dispatch_commitment_id"]
            .as_str()
            .ok_or("original dispatch ID")?
    );
    assert_eq!(
        original.live_request_digest().as_str(),
        value["live_request_digest"]
            .as_str()
            .ok_or("original full request digest")?
    );
    assert_eq!(
        original.native_dispatch_ledger_digest(),
        operation.native_dispatch_ledger_digest()
    );
    assert_eq!(
        original.native_dispatch_ledger_digest(),
        Some(&ledger.record_digest)
    );
    let context = persisted
        .security_invocation_context
        .as_ref()
        .ok_or("original context")?;
    raw.validate_original_native_dispatch_record(
        ledger,
        context,
        u32::try_from(
            value["grant_index"]
                .as_u64()
                .ok_or("original grant index")?,
        )?,
    )?;
    let retained = persisted
        .request_canonical_json
        .as_ref()
        .ok_or("stripped original request")?;
    let retained_request: chio_kernel::ToolCallRequest = serde_json::from_str(retained)?;
    assert!(retained_request.execution_nonce.is_none());
    assert!(retained_request.dpop_proof.is_none());
    assert!(retained_request.supplemental_authorization.is_none());
    assert!(retained_request.declassification_grant.is_none());
    // Every actual native caller start had a signed nonce. Its complete
    // original input cannot be replaced by these credential-stripped bytes.
    assert_ne!(
        original.live_request_digest().as_str(),
        chio_core::sha256_hex(retained.as_bytes())
    );
    Ok(())
}
