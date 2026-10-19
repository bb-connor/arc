use super::*;

fn record_with_schema(
    schema: &str,
    omit_commitment: bool,
) -> TestResult<(
    NativeSecurityDispatchLedgerRecordV1,
    SecurityInvocationContext,
)> {
    let (kernel, request, context, store) = native_egress::fixture("ledger-wire-contract")?;
    let operation = store.operation();
    let prepared = kernel.prepare_native_security_egress(
        operation.binding().operation_id(),
        &request,
        &context,
    )?;
    let record = prepared.retain_dispatch_ledger(0, b"{}")?;
    let mut value: serde_json::Value = serde_json::from_slice(&record.canonical_record)?;
    value["schema"] = serde_json::json!(schema);
    if omit_commitment {
        value
            .as_object_mut()
            .ok_or("ledger object")?
            .remove("original_dispatch_commitment_id");
    }
    let canonical_record = canonical_json_bytes(&value)?;
    Ok((
        NativeSecurityDispatchLedgerRecordV1 {
            operation_id: record.operation_id,
            record_digest: AdmissionDigest::try_new("ledger", sha256_hex(&canonical_record))?,
            canonical_record,
        },
        context,
    ))
}

#[test]
fn native_ledger_v1_accepts_required_original_commitment() -> TestResult {
    let (record, context) =
        record_with_schema("chio.native-dispatch-preparation-ledger.v1", false)?;
    assert!(NativeSecurityDispatchRequestBindingV1::from_ledger(&record, &context).is_ok());
    Ok(())
}

#[test]
fn native_ledger_v1_rejects_v2_with_original_commitment() -> TestResult {
    let (record, context) =
        record_with_schema("chio.native-dispatch-preparation-ledger.v2", false)?;
    assert!(matches!(
        NativeSecurityDispatchRequestBindingV1::from_ledger(&record, &context),
        Err(AdmissionOperationStoreError::Invariant(detail))
            if detail == "original native ledger schema is invalid"
    ));
    Ok(())
}

#[test]
fn native_ledger_v1_rejects_missing_original_commitment() -> TestResult {
    let (record, context) = record_with_schema("chio.native-dispatch-preparation-ledger.v1", true)?;
    assert!(matches!(
        NativeSecurityDispatchRequestBindingV1::from_ledger(&record, &context),
        Err(AdmissionOperationStoreError::Operation(AdmissionOperationError::UntrustedInput(error)))
            if error.code() == "urn:chio:error:attest:signed-json-invalid-shape"
    ));
    Ok(())
}
