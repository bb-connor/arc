use super::*;

#[test]
fn top_level_durable_admission_commits_before_dispatch_and_blocks_replay() {
    let (kernel, request, store, invocations) = durable_admission_fixture("durable-top-level");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("first durable dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("exact replay delivery");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut conflict = request.clone();
    conflict.arguments = serde_json::json!({"record": "ledger-7", "value": "reopened"});
    let conflict = kernel
        .evaluate_tool_call_blocking(&conflict)
        .expect("conflicting replay denial");
    assert_eq!(conflict.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_completion_projects_the_canonical_receipt_idempotently() {
    let (mut kernel, request, _store, invocations) =
        durable_admission_fixture("durable-receipt-projection");
    let projection = AdmissionReceiptProjectionStore::default();
    kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable receipt projection");
    assert_same_receipt(
        projection.receipt().as_ref().expect("projected receipt"),
        &response.receipt,
    );
    assert_eq!(projection.successful_appends(), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("idempotent durable receipt projection replay");
    assert_same_receipt(&replay.receipt, &response.receipt);
    assert_eq!(projection.successful_appends(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn completed_replay_heals_a_failed_receipt_projection_without_redispatch() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-receipt-projection-recovery");
    let projection = AdmissionReceiptProjectionStore::default();
    projection.fail_next_append();
    kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("receipt projection failure must fail closed");
    assert!(error
        .to_string()
        .contains("injected admission receipt projection failure"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert!(projection.receipt().is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("completed replay must heal receipt projection");
    assert_same_receipt(
        projection.receipt().as_ref().expect("healed receipt"),
        &replay.receipt,
    );
    assert_eq!(projection.successful_appends(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn completed_federated_replay_remains_closed_until_cosign_succeeds(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture("durable-federation-cosign-retry");
    kernel.set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))?;

    let origin_keypair = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let local_kernel_id = "kernel.org-b";
    kernel.set_federation_local_kernel_id(local_kernel_id);
    let trust = KernelTrustExchange::new(local_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_keypair.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_keypair, now);
    let mut kernel = kernel.with_federation_peers(vec![peer]);
    kernel.set_runtime_admission_hook(std::sync::Arc::new(TreatyDsseAdmissionHook::new(
        origin_keypair,
        kernel.config.keypair.clone(),
    )));
    let cosigner_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(std::sync::Arc::new(CountingRejectingCosigner {
        calls: std::sync::Arc::clone(&cosigner_calls),
    }));
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_owned());

    assert!(matches!(
        kernel.evaluate_tool_call_blocking(&request),
        Err(KernelError::Internal(reason)) if reason.contains("bilateral co-sign failed")
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(cosigner_calls.load(Ordering::SeqCst), 1);

    assert!(matches!(
        kernel.evaluate_tool_call_blocking(&request),
        Err(KernelError::Internal(reason)) if reason.contains("bilateral co-sign failed")
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(cosigner_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn admission_receipt_reconciliation_heals_a_crash_gap_before_serving() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-receipt-startup-recovery");
    let completed = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("canonical admission completion");

    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    let projection = AdmissionReceiptProjectionStore::default();
    recovered_kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), admission_test_fence())
        .expect("qualified admission store");

    assert_eq!(
        recovered_kernel
            .reconcile_durable_admission_receipt_projections()
            .expect("startup receipt reconciliation"),
        1
    );
    assert_same_receipt(
        projection.receipt().as_ref().expect("reconciled receipt"),
        &completed.receipt,
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_tool_return_persistence_retains_dispatch_and_blocks_redispatch() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-return-write-failure");
    store.fail_next_outcome_write();

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("tool return journal failure must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason)
            if reason.contains("injected tool outcome write failure")
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let failure_receipt = receipt_log.get(0).expect("tool return failure receipt");
    assert!(failure_receipt.is_denied());
    assert!(failure_receipt.verify_signature().expect("signed receipt"));

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("retained dispatch must produce a denial");
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("DispatchCommitted")));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_terminal_projection_retains_finalizing_operation_and_blocks_redispatch() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-terminal-projection-failure");
    store.fail_next_terminal_projection();

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("terminal projection failure must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason)
            if reason.contains("injected terminal projection failure")
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("retained finalization must recover delivery");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn finalization_recovers_before_evaluation_creation() {
    assert_finalization_crash_recovers(
        "durable-evaluation-begin-failure",
        TestAdmissionOperationStore::fail_next_evaluation_begin,
        "injected evaluation begin failure",
        (None, Some(1)),
    );
}

#[test]
fn finalization_recovers_after_frozen_evaluation_creation() {
    assert_finalization_crash_recovers(
        "durable-evaluation-stage-failure",
        TestAdmissionOperationStore::fail_next_evaluation_stage,
        "injected evaluation stage failure",
        (Some(1), Some(1)),
    );
}

#[test]
fn finalization_recovers_after_pure_result_staging() {
    assert_finalization_crash_recovers(
        "durable-evaluation-finalization-failure",
        TestAdmissionOperationStore::fail_next_evaluation_finalization,
        "injected evaluation finalization failure",
        (Some(2), Some(1)),
    );
}

#[test]
fn finalization_recovers_after_store_owner_rotation() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-owner-rotation-recovery");
    store.fail_next_evaluation_begin();

    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash must fail closed");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let rotated_fence = StoreMutationFence {
        store_uuid: admission_test_fence().store_uuid,
        lease_id: "test-admission-lease-2".to_owned(),
        owner_epoch: 2,
    };
    store.rotate_fence(rotated_fence.clone());
    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), rotated_fence)
        .expect("rotated qualified admission store");
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let recovered = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect("new serving owner must finish retained finalization");
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
