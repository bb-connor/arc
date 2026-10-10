//! The terminal receipt outbox consumer against more than one bounded page of
//! permanently failing outboxes ahead of a healthy one.

use super::*;
use crate::security_admission_operation::{
    InMemoryAdmissionOperationStore, PreparedAdmissionOperation,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FAILING_HEADS: usize = MAX_TERMINAL_RECEIPT_RECOVERY_OPERATIONS_PER_ACTIVATION + 1;

fn recovering_kernel() -> ChioKernel {
    ChioKernel::new_with_clock(
        KernelConfig {
            keypair: chio_core::Keypair::generate(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: sha256_hex(b"pending-terminal-receipt-cursor"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: crate::MemoryBudgetConfig::defaults(),
            deadlines: crate::HotPathDeadlineConfig::default(),
        },
        chio_test_support::clock::clock(),
    )
}

fn governed_response(
    kernel: &ChioKernel,
    coordinator_authority_id: &str,
    request_id: &str,
) -> Result<AdmissionOperation, crate::security_admission_operation::AdmissionOperationError> {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: coordinator_authority_id.to_string(),
        request_id: request_id.to_string(),
        capability_id: "compensated-operator".to_string(),
        authorization_capability_hash: sha256_hex(b"compensated-operator"),
        request_binding_hash: sha256_hex(request_id.as_bytes()),
        policy_hash: kernel.config.policy_hash.clone(),
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: None,
        execution_nonce_id: None,
        coordinator_lease_epoch: 1,
    })
}

fn compensated_with_pending_receipt(
    kernel: &ChioKernel,
    store: &InMemoryAdmissionOperationStore,
    prepared: AdmissionOperation,
) -> TestResult<AdmissionOperation> {
    store.create_prepared(prepared.clone())?;
    let pending = kernel.stage_compensation_pending_with_terminal_receipt(
        store,
        &prepared,
        "compensated before dispatch",
    )?;
    let payload = kernel.validate_staged_compensation_receipt(store, &pending)?;
    let terminal = pending.transition_checked(
        AdmissionOperationState::CompensatedBeforeDispatch,
        AdmissionDispatchState::NotStarted,
        pending.coordinator_lease_epoch(),
        pending.last_error().map(ToOwned::to_owned),
    )?;
    Ok(kernel.stage_terminal_receipt_outbox_with_store(store, &pending, &terminal, &payload)?)
}

fn receipt_state(
    store: &InMemoryAdmissionOperationStore,
    operation_id: &str,
) -> TestResult<AdmissionCleanupActionState> {
    match store.load_cleanup_actions(operation_id)?.as_slice() {
        [receipt] if receipt.kind() == AdmissionCleanupActionKind::TerminalReceipt => {
            Ok(receipt.state())
        }
        other => Err(format!("unexpected outbox journal: {other:?}").into()),
    }
}

fn stage_failing_heads(
    kernel: &ChioKernel,
    store: &InMemoryAdmissionOperationStore,
    retained_authority: &str,
    indexes: std::ops::Range<usize>,
    heads: &mut Vec<String>,
) -> TestResult {
    for index in indexes {
        let prepared = governed_response(kernel, retained_authority, &format!("retained-{index}"))?;
        let head = compensated_with_pending_receipt(kernel, store, prepared)?;
        heads.push(head.operation_id().to_string());
    }
    heads.sort_unstable();
    Ok(())
}

fn stage_tail_after_heads(
    kernel: &ChioKernel,
    store: &InMemoryAdmissionOperationStore,
    recovering_authority: &str,
    label: &str,
    heads: &[String],
) -> TestResult<AdmissionOperation> {
    let last_head = heads.last().ok_or("failing heads")?;
    let tail = (0..1_000_000)
        .find_map(|index| {
            governed_response(kernel, recovering_authority, &format!("{label}-{index}"))
                .ok()
                .filter(|operation| operation.operation_id() > last_head.as_str())
        })
        .ok_or("healthy tail after every failing head")?;
    compensated_with_pending_receipt(kernel, store, tail)
}

fn bounded_refusal(failed: usize, first_head: &str) -> String {
    format!(
        "one or more terminal receipt outboxes remain unfinished: {failed} failed, first operation {first_head}: {}",
        KernelError::Internal(format!(
            "terminal receipt operation {first_head} belongs to a different coordinator authority"
        ))
    )
}

fn refusal_detail(recovery: &Result<usize, KernelError>) -> TestResult<String> {
    match recovery {
        Err(KernelError::Internal(detail)) => Ok(detail.clone()),
        other => Err(format!("{:.1024}", format!("{other:?}")).into()),
    }
}

#[test]
fn recovery_drains_a_healthy_outbox_behind_more_than_one_page_of_failing_heads() -> TestResult {
    let kernel = recovering_kernel();
    let store = InMemoryAdmissionOperationStore::new();
    let retained_authority = sha256_hex(b"retained-coordinator-authority");
    let recovering_authority = sha256_hex(b"recovering-coordinator-authority");
    let mut heads = Vec::with_capacity(FAILING_HEADS);
    stage_failing_heads(
        &kernel,
        &store,
        &retained_authority,
        0..FAILING_HEADS,
        &mut heads,
    )?;
    let tail =
        stage_tail_after_heads(&kernel, &store, &recovering_authority, "recovering", &heads)?;
    let mut inventory = heads.clone();
    inventory.push(tail.operation_id().to_string());
    assert_eq!(
        store.list_operations_with_pending_cleanup_action(
            AdmissionOperationKind::GovernedActiveResponse,
            AdmissionCleanupActionKind::TerminalReceipt,
            FAILING_HEADS + 1,
        )?,
        inventory
    );

    let recovery = kernel.recover_terminal_receipt_outboxes_with_store(
        &store,
        AdmissionOperationKind::GovernedActiveResponse,
        Some(&recovering_authority),
    );

    assert_eq!(
        receipt_state(&store, tail.operation_id())?,
        AdmissionCleanupActionState::Completed,
        "healthy outbox behind {FAILING_HEADS} failing heads"
    );
    assert_eq!(store.load(tail.operation_id())?, Some(tail.clone()));
    for head in &heads {
        assert_eq!(
            receipt_state(&store, head)?,
            AdmissionCleanupActionState::Pending
        );
    }
    let first_head = heads.first().ok_or("failing heads")?;
    let expected = bounded_refusal(FAILING_HEADS, first_head);
    assert!(
        matches!(&recovery, Err(KernelError::Internal(detail)) if detail == &expected),
        "{:.1024}",
        format!("{recovery:?}")
    );
    Ok(())
}

#[test]
fn recovery_refusal_keeps_one_failure_and_a_count_as_failing_heads_grow() -> TestResult {
    let kernel = recovering_kernel();
    let store = InMemoryAdmissionOperationStore::new();
    let retained_authority = sha256_hex(b"retained-coordinator-authority");
    let recovering_authority = sha256_hex(b"recovering-coordinator-authority");
    let mut heads = Vec::new();
    stage_failing_heads(
        &kernel,
        &store,
        &retained_authority,
        0..FAILING_HEADS,
        &mut heads,
    )?;
    let first_tail =
        stage_tail_after_heads(&kernel, &store, &recovering_authority, "first", &heads)?;
    let first_recovery = kernel.recover_terminal_receipt_outboxes_with_store(
        &store,
        AdmissionOperationKind::GovernedActiveResponse,
        Some(&recovering_authority),
    );
    let first_detail = refusal_detail(&first_recovery)?;
    assert_eq!(
        first_detail,
        bounded_refusal(FAILING_HEADS, heads.first().ok_or("failing heads")?)
    );

    let grown = FAILING_HEADS + MAX_TERMINAL_RECEIPT_RECOVERY_OPERATIONS_PER_ACTIVATION;
    stage_failing_heads(
        &kernel,
        &store,
        &retained_authority,
        FAILING_HEADS..grown,
        &mut heads,
    )?;
    let second_tail =
        stage_tail_after_heads(&kernel, &store, &recovering_authority, "second", &heads)?;
    let mut inventory = heads.clone();
    inventory.push(second_tail.operation_id().to_string());
    assert_eq!(
        store.list_operations_with_pending_cleanup_action(
            AdmissionOperationKind::GovernedActiveResponse,
            AdmissionCleanupActionKind::TerminalReceipt,
            grown + 1,
        )?,
        inventory
    );

    let second_recovery = kernel.recover_terminal_receipt_outboxes_with_store(
        &store,
        AdmissionOperationKind::GovernedActiveResponse,
        Some(&recovering_authority),
    );
    let second_detail = refusal_detail(&second_recovery)?;

    assert_eq!(
        second_detail,
        bounded_refusal(grown, heads.first().ok_or("failing heads")?)
    );
    assert_eq!(second_detail.len(), first_detail.len());
    for tail in [&first_tail, &second_tail] {
        assert_eq!(
            receipt_state(&store, tail.operation_id())?,
            AdmissionCleanupActionState::Completed
        );
        assert_eq!(store.load(tail.operation_id())?, Some(tail.clone()));
    }
    assert_eq!(heads.len(), grown);
    for head in &heads {
        assert_eq!(
            receipt_state(&store, head)?,
            AdmissionCleanupActionState::Pending
        );
    }
    Ok(())
}
