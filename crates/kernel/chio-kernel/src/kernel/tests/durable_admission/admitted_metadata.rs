//! Caller receipt metadata is retained with the original request and signed
//! unchanged into every canonical refusal for that operation.
use super::*;
use crate::admission_operation::RetainedToolAdmissionRequestV1;
use crate::kernel::admission_coordinator::DispatchTransport;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn admitted() -> serde_json::Value {
    serde_json::json!({
        "chio_process": {
            "runtime_id": "runtime-admitted",
            "process_id": "alice",
            "operation_key": "operation-1",
            "attempt": 1,
        }
    })
}

fn begin_admitted(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    metadata: &serde_json::Value,
) -> Result<DurableToolAdmission, Box<dyn std::error::Error>> {
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    Ok(kernel
        .begin_durable_tool_admission_for_transport(
            request,
            &matching,
            None,
            Some(metadata),
            current_unix_timestamp_ms(),
            DispatchTransport::KernelToolServer,
        )
        .map_err(|failure| *failure.error)?
        .ok_or("covered durable admission")?)
}

fn canonical(receipt: &ChioReceipt) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(chio_core::canonical::canonical_json_bytes(receipt)?)
}

#[test]
fn recovery_refusal_signs_the_admitted_caller_metadata() -> TestResult {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("admitted-metadata-recovery");
    let admission = begin_admitted(&kernel, &request, &admitted())?;
    let retained = store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .retained_request
        .clone()
        .ok_or("retained original request")?;
    assert_eq!(retained.admitted_receipt_metadata(), admitted().as_object());
    drop(admission);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let receipt = store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .receipt
        .clone()
        .ok_or("recovery refusal receipt")?;
    assert!(receipt.verify_signature()?);
    let metadata = receipt.metadata.as_ref().ok_or("receipt metadata")?;
    assert_eq!(metadata.get("chio_process"), admitted().get("chio_process"));
    assert_eq!(
        metadata.pointer("/chio_runtime/identity_disposition"),
        Some(&serde_json::json!("terminal"))
    );

    let receipts = kernel.receipt_log().len();
    let replay = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(admitted()))?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(canonical(&replay.receipt)?, canonical(&receipt)?);
    assert_eq!(kernel.receipt_log().len(), receipts);

    let mut changed = admitted();
    changed["chio_process"]["attempt"] = serde_json::json!(2);
    let conflict = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(changed));
    let expected = format!(
        "request id conflicts with retained operation {}",
        store.operation().binding().operation_id().as_str()
    );
    assert!(
        matches!(&conflict, Err(KernelError::DurableAdmission(reason)) if reason == &expected),
        "{conflict:?}"
    );
    assert_eq!(kernel.receipt_log().len(), receipts);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn recovery_refuses_retained_metadata_outside_the_admission_binding() -> TestResult {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("admitted-metadata-tampered");
    let admission = begin_admitted(&kernel, &request, &admitted())?;
    drop(admission);
    let before = store.operation();
    {
        let mut state = store.state.lock().map_err(|_| "state lock")?;
        let original = state
            .retained_request
            .as_ref()
            .ok_or("retained original request")?;
        let mut wire: serde_json::Value = serde_json::from_slice(original.canonical_bytes())?;
        wire["admitted_receipt_metadata"]["chio_process"]["process_id"] =
            serde_json::json!("mallory");
        state.retained_request = Some(RetainedToolAdmissionRequestV1::from_canonical_bytes(
            &chio_core::canonical::canonical_json_bytes(&wire)?,
        )?);
    }
    let result = kernel.reconcile_recoverable_admissions();
    assert!(
        matches!(&result, Err(error) if error.to_string().contains("retained request does not match its admission binding")),
        "{result:?}"
    );
    assert_eq!(store.operation(), before);
    assert!(store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .receipt
        .is_none());
    assert!(kernel.receipt_log().is_empty());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn kernel_derived_metadata_keys_are_refused_before_admission() -> TestResult {
    for key in ["admission_operation", "attribution", "chio_runtime"] {
        let (kernel, request, store, invocations) =
            durable_admission_fixture("admitted-metadata-reserved");
        let error = kernel
            .evaluate_tool_call_blocking_with_metadata(
                &request,
                Some(serde_json::json!({ key: {"operation_id": "forged"} })),
            )
            .err()
            .ok_or("reserved receipt metadata was admitted")?;
        let expected = match key {
            "chio_runtime" => {
                "chio_runtime is reserved for kernel-derived runtime admission reservations"
                    .to_owned()
            }
            _ => format!("{key} is reserved for kernel-derived receipts"),
        };
        assert!(
            matches!(&error, KernelError::InvalidReceiptMetadata(reason) if reason == &expected),
            "{error:?}"
        );
        let state = store.state.lock().map_err(|_| "state lock")?;
        assert!(state.operation.is_none());
        assert!(state.retained_request.is_none());
        assert!(kernel.receipt_log().is_empty());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
