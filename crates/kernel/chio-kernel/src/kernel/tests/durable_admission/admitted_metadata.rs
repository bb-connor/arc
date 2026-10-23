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
    assert!(receipt.verify_integrity_embedded_key()?);
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

fn launched(id: char) -> serde_json::Value {
    let mut metadata = admitted();
    metadata["native_launch"] = serde_json::json!({
        "receipt_id": id.to_string().repeat(64),
        "receipt_sha256": "d".repeat(64),
    });
    metadata
}

fn stored_receipt(
    store: &TestAdmissionOperationStore,
) -> Result<ChioReceipt, Box<dyn std::error::Error>> {
    Ok(store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .receipt
        .clone()
        .ok_or("canonical refusal receipt")?)
}

#[test]
fn only_the_native_and_worker_launches_are_attempt_scoped_admitted_metadata() {
    let paths: [&[&str]; 2] = [&["native_launch"], &["chio_process", "worker_profile"]];
    assert_eq!(
        crate::admission_operation::ATTEMPT_SCOPED_RECEIPT_METADATA_PATHS,
        paths
    );
}

#[test]
fn a_relaunched_caller_replays_the_admission_named_by_its_admitting_launch() -> TestResult {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("admitted-metadata-relaunch");
    let admission = begin_admitted(&kernel, &request, &launched('a'))?;
    drop(admission);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    let receipt = stored_receipt(&store)?;
    assert!(receipt.verify_integrity_embedded_key()?);
    let metadata = receipt.metadata.as_ref().ok_or("receipt metadata")?;
    assert_eq!(
        metadata.get("native_launch"),
        launched('a').get("native_launch"),
        "a recovery refusal names the launch that admitted the call"
    );
    assert_eq!(metadata.get("chio_process"), admitted().get("chio_process"));

    let receipts = kernel.receipt_log().len();
    let replay = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(launched('b')))?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(canonical(&replay.receipt)?, canonical(&receipt)?);
    assert_eq!(kernel.receipt_log().len(), receipts);

    let missing = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(admitted()));
    assert!(
        matches!(&missing, Err(KernelError::AdmissionRecovery(error))
            if matches!(error.as_ref(), crate::admission_operation::AdmissionRecoveryError::Store(
                crate::admission_operation::AdmissionOperationStoreError::Invariant(reason)
            ) if reason == "original request is missing or changed")),
        "{missing:?}"
    );

    let expected = format!(
        "request id conflicts with retained operation {}",
        store.operation().binding().operation_id().as_str()
    );
    for (field, value) in [
        ("runtime_id", serde_json::json!("runtime-other")),
        ("process_id", serde_json::json!("mallory")),
        ("operation_key", serde_json::json!("operation-2")),
        ("attempt", serde_json::json!(2)),
        ("request_sha256", serde_json::json!("e".repeat(64))),
    ] {
        let mut changed = launched('b');
        changed["chio_process"][field] = value;
        let conflict = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(changed));
        assert!(
            matches!(&conflict, Err(KernelError::DurableAdmission(reason)) if reason == &expected),
            "{field}: {conflict:?}"
        );
    }
    let mut routed = launched('b');
    routed["route"] = serde_json::json!({"selectedRoute": "other"});
    let conflict = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(routed));
    assert!(
        matches!(&conflict, Err(KernelError::DurableAdmission(reason)) if reason == &expected),
        "{conflict:?}"
    );
    assert_eq!(kernel.receipt_log().len(), receipts);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn malformed_native_launch_metadata_is_refused_before_admission() -> TestResult {
    for launch in [
        serde_json::json!("launch"),
        serde_json::json!({"receipt_id": "a".repeat(64)}),
        serde_json::json!({"receipt_id": "A".repeat(64), "receipt_sha256": "d".repeat(64)}),
        serde_json::json!({"receipt_id": "a".repeat(63), "receipt_sha256": "d".repeat(64)}),
        serde_json::json!({"receipt_id": "a".repeat(64), "receipt_sha256": "d".repeat(64), "extra": 1}),
    ] {
        let (kernel, request, store, invocations) =
            durable_admission_fixture("admitted-metadata-malformed-launch");
        let mut metadata = admitted();
        metadata["native_launch"] = launch;
        let error = kernel
            .evaluate_tool_call_blocking_with_metadata(&request, Some(metadata))
            .err()
            .ok_or("malformed native launch was admitted")?;
        assert!(
            matches!(&error, KernelError::InvalidReceiptMetadata(reason)
                if reason == "native_launch must name one launch receipt id and sha256"),
            "{error:?}"
        );
        assert!(store
            .state
            .lock()
            .map_err(|_| "state lock")?
            .operation
            .is_none());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

fn profiled(attempt: u32, id: char) -> serde_json::Value {
    let mut metadata = admitted();
    metadata["chio_process"]["worker_profile"] = serde_json::json!({
        "kind": "container",
        "launch_attempt": attempt,
        "launch_ref": {"record_id": id.to_string().repeat(64), "record_sha256": "e".repeat(64)},
    });
    metadata
}

#[test]
fn a_relaunched_worker_replays_the_admission_named_by_its_admitting_profile() -> TestResult {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("admitted-metadata-worker-relaunch");
    let admission = begin_admitted(&kernel, &request, &profiled(1, 'a'))?;
    drop(admission);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    let receipt = stored_receipt(&store)?;
    assert_eq!(
        receipt
            .metadata
            .as_ref()
            .ok_or("receipt metadata")?
            .pointer("/chio_process/worker_profile"),
        profiled(1, 'a').pointer("/chio_process/worker_profile")
    );
    let receipts = kernel.receipt_log().len();
    let replay =
        kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(profiled(2, 'b')))?;
    assert_eq!(canonical(&replay.receipt)?, canonical(&receipt)?);
    assert_eq!(kernel.receipt_log().len(), receipts);
    let missing = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(admitted()));
    assert!(
        matches!(&missing, Err(KernelError::AdmissionRecovery(error))
            if matches!(error.as_ref(), crate::admission_operation::AdmissionRecoveryError::Store(
                crate::admission_operation::AdmissionOperationStoreError::Invariant(reason)
            ) if reason == "original request is missing or changed")),
        "{missing:?}"
    );
    assert_eq!(kernel.receipt_log().len(), receipts);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn malformed_worker_profile_metadata_is_refused_before_admission() -> TestResult {
    let reference =
        serde_json::json!({"record_id": "a".repeat(64), "record_sha256": "e".repeat(64)});
    for profile in [
        serde_json::json!("container"),
        serde_json::json!({"kind": "direct", "launch_attempt": 1, "launch_ref": reference}),
        serde_json::json!({"kind": "container", "launch_attempt": 0, "launch_ref": reference}),
        serde_json::json!({"kind": "container", "launch_attempt": 1}),
        serde_json::json!({"kind": "container", "launch_attempt": 1,
            "launch_ref": {"record_id": "a".repeat(64)}}),
        serde_json::json!({"kind": "container", "launch_attempt": 1,
            "launch_ref": {"record_id": "a".repeat(64), "record_sha256": "E".repeat(64)}}),
        serde_json::json!({"kind": "container", "launch_attempt": 1, "launch_ref": reference,
            "extra": true}),
    ] {
        let (kernel, request, store, invocations) =
            durable_admission_fixture("admitted-metadata-malformed-profile");
        let mut metadata = admitted();
        metadata["chio_process"]["worker_profile"] = profile;
        let error = kernel
            .evaluate_tool_call_blocking_with_metadata(&request, Some(metadata))
            .err()
            .ok_or("malformed worker profile was admitted")?;
        assert!(
            matches!(&error, KernelError::InvalidReceiptMetadata(reason)
                if reason == "chio_process.worker_profile must name one container launch record and attempt"),
            "{error:?}"
        );
        assert!(store
            .state
            .lock()
            .map_err(|_| "state lock")?
            .operation
            .is_none());
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
