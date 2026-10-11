//! Terminal immutability, pending-outbox traversal, request-id ownership and
//! the terminal receipt insert boundary of the in-memory store.

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const COMPLETED_IS_IMMUTABLE: &str = "terminal admission operation in `completed` is immutable";
const OUTCOME_UNKNOWN_IS_IMMUTABLE: &str =
    "terminal admission operation in `outcome_unknown_after_dispatch` is immutable";
const TERMINAL_RECOVERY_CLAIM: &str = "terminal admission operation cannot be claimed for recovery";
const OUT_OF_BAND_TERMINAL_RECEIPT: &str =
    "terminal receipt outbox must be inserted by its atomic terminal transition";
const REQUEST_OWNER_CONFLICT: &str =
    "request_id `request-owner` is already owned by another tool_dispatch operation";
const PAGE_LIMIT: usize = 4;

fn governed_response(request_id: &str) -> Result<AdmissionOperation, AdmissionOperationError> {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: "coordinator-1".to_string(),
        request_id: request_id.to_string(),
        capability_id: "capability-1".to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: "33".repeat(32),
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: Some("44".repeat(32)),
        execution_nonce_id: None,
        coordinator_lease_epoch: 7,
    })
}

fn tool_dispatch(
    capability_id: &str,
    request_binding_hash: &str,
    budget_hold_id: &str,
) -> Result<AdmissionOperation, AdmissionOperationError> {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: "coordinator-1".to_string(),
        request_id: "request-owner".to_string(),
        capability_id: capability_id.to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: request_binding_hash.to_string(),
        policy_hash: "33".repeat(32),
        broker_attempt_id: Some("attempt-1".to_string()),
        budget_hold_id: Some(budget_hold_id.to_string()),
        approval_set_hash: Some("44".repeat(32)),
        execution_nonce_id: Some("nonce-1".to_string()),
        coordinator_lease_epoch: 7,
    })
}

fn transition<'a>(
    current: &'a AdmissionOperation,
    next_state: AdmissionOperationState,
    next_dispatch_state: AdmissionDispatchState,
    next_coordinator_lease_epoch: u64,
    last_error: Option<&str>,
) -> AdmissionOperationCompareAndSwap<'a> {
    AdmissionOperationCompareAndSwap {
        operation_id: current.operation_id(),
        expected_version: current.version(),
        coordinator_lease_epoch: current.coordinator_lease_epoch(),
        next_state,
        next_dispatch_state,
        next_coordinator_lease_epoch,
        last_error: last_error.map(ToOwned::to_owned),
    }
}

fn applied(outcome: AdmissionOperationCasOutcome) -> TestResult<AdmissionOperation> {
    match outcome {
        AdmissionOperationCasOutcome::Applied(operation) => Ok(operation),
        other => Err(format!("transition did not apply: {other:?}").into()),
    }
}

fn dispatch_committed(
    store: &InMemoryAdmissionOperationStore,
    request_id: &str,
) -> TestResult<AdmissionOperation> {
    let prepared = governed_response(request_id)?;
    store.create_prepared(prepared.clone())?;
    let reserved = applied(store.compare_and_swap(transition(
        &prepared,
        AdmissionOperationState::ApprovalReserved,
        AdmissionDispatchState::NotStarted,
        7,
        None,
    ))?)?;
    applied(store.compare_and_swap(transition(
        &reserved,
        AdmissionOperationState::DispatchCommitted,
        AdmissionDispatchState::Committed,
        7,
        None,
    ))?)
}

fn terminal_with_pending_receipt(
    store: &InMemoryAdmissionOperationStore,
    request_id: &str,
    state: AdmissionOperationState,
    dispatch_state: AdmissionDispatchState,
    last_error: Option<&str>,
) -> TestResult<(AdmissionOperation, AdmissionCleanupAction)> {
    let committed = dispatch_committed(store, request_id)?;
    let receipt = AdmissionCleanupAction::pending(
        &committed,
        AdmissionCleanupActionKind::TerminalReceipt,
        &serde_json::json!({"terminal": state.as_str()}),
    )?;
    let terminal = applied(store.compare_and_swap_with_cleanup_action(
        transition(&committed, state, dispatch_state, 7, last_error),
        receipt.clone(),
    )?)?;
    Ok((terminal, receipt))
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

fn pending_receipt_page(
    store: &InMemoryAdmissionOperationStore,
    after_operation_id: Option<&str>,
    limit: usize,
) -> Result<Vec<String>, AdmissionOperationError> {
    store.list_operations_with_pending_cleanup_action_page(
        AdmissionOperationKind::GovernedActiveResponse,
        AdmissionCleanupActionKind::TerminalReceipt,
        after_operation_id,
        limit,
    )
}

#[test]
fn completed_row_refuses_a_lease_only_rewrite_beside_its_pending_receipt() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let (terminal, receipt) = terminal_with_pending_receipt(
        &store,
        "terminal-completed",
        AdmissionOperationState::Completed,
        AdmissionDispatchState::EffectCompleted,
        None,
    )?;
    assert_eq!(
        (terminal.state(), receipt.state(), receipt.version()),
        (
            AdmissionOperationState::Completed,
            AdmissionCleanupActionState::Pending,
            0
        )
    );

    let rewrite = store.compare_and_swap_with_cleanup_action(
        transition(
            &terminal,
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
            terminal.coordinator_lease_epoch() + 1,
            Some("rewritten terminal row"),
        ),
        receipt.clone(),
    );

    assert!(
        matches!(&rewrite, Err(AdmissionOperationError::Invalid(message)) if message == COMPLETED_IS_IMMUTABLE),
        "{rewrite:?}"
    );
    assert_eq!(store.load(terminal.operation_id())?, Some(terminal.clone()));
    assert_eq!(
        store.load_cleanup_actions(terminal.operation_id())?,
        vec![receipt]
    );
    Ok(())
}

#[test]
fn outcome_unknown_row_refuses_a_lease_only_rewrite_beside_its_pending_receipt() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let (terminal, receipt) = terminal_with_pending_receipt(
        &store,
        "terminal-outcome-unknown",
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        AdmissionDispatchState::OutcomeUnknown,
        Some("dispatch outcome unknown"),
    )?;
    assert_eq!(
        (terminal.state(), receipt.state(), receipt.version()),
        (
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
            AdmissionCleanupActionState::Pending,
            0
        )
    );

    let rewrite = store.compare_and_swap_with_cleanup_action(
        transition(
            &terminal,
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
            AdmissionDispatchState::OutcomeUnknown,
            terminal.coordinator_lease_epoch() + 1,
            Some("rewritten terminal row"),
        ),
        receipt.clone(),
    );

    assert!(
        matches!(&rewrite, Err(AdmissionOperationError::Invalid(message)) if message == OUTCOME_UNKNOWN_IS_IMMUTABLE),
        "{rewrite:?}"
    );
    assert_eq!(store.load(terminal.operation_id())?, Some(terminal.clone()));
    assert_eq!(
        store.load_cleanup_actions(terminal.operation_id())?,
        vec![receipt]
    );
    Ok(())
}

#[test]
fn terminal_transition_checked_refuses_lease_renewal_and_same_epoch_rewrite() -> TestResult {
    let completed = governed_response("terminal-projection")?
        .transition_checked(
            AdmissionOperationState::ApprovalReserved,
            AdmissionDispatchState::NotStarted,
            7,
            None,
        )?
        .transition_checked(
            AdmissionOperationState::DispatchCommitted,
            AdmissionDispatchState::Committed,
            7,
            None,
        )?
        .transition_checked(
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
            7,
            None,
        )?;

    let renewal = completed.transition_checked(
        AdmissionOperationState::Completed,
        AdmissionDispatchState::EffectCompleted,
        completed.coordinator_lease_epoch() + 1,
        None,
    );
    assert!(
        matches!(&renewal, Err(AdmissionOperationError::Invalid(message)) if message == COMPLETED_IS_IMMUTABLE),
        "{renewal:?}"
    );
    let same_epoch = completed.transition_checked(
        AdmissionOperationState::Completed,
        AdmissionDispatchState::EffectCompleted,
        completed.coordinator_lease_epoch(),
        None,
    );
    assert!(
        matches!(&same_epoch, Err(AdmissionOperationError::Invalid(message)) if message == COMPLETED_IS_IMMUTABLE),
        "{same_epoch:?}"
    );
    Ok(())
}

#[test]
fn outcome_unknown_row_refuses_a_recovery_claim() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let (terminal, receipt) = terminal_with_pending_receipt(
        &store,
        "terminal-recovery-claim",
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        AdmissionDispatchState::OutcomeUnknown,
        Some("dispatch outcome unknown"),
    )?;

    let claim = store.claim_recovery(
        terminal.operation_id(),
        terminal.version(),
        terminal.coordinator_lease_epoch(),
    );

    assert!(
        matches!(&claim, Err(AdmissionOperationError::Invalid(message)) if message == TERMINAL_RECOVERY_CLAIM),
        "{claim:?}"
    );
    assert_eq!(store.load(terminal.operation_id())?, Some(terminal.clone()));
    assert_eq!(
        store.load_cleanup_actions(terminal.operation_id())?,
        vec![receipt]
    );
    Ok(())
}

#[test]
fn terminal_receipt_outbox_retries_and_acknowledges_on_an_immutable_row() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let committed = dispatch_committed(&store, "terminal-acknowledged")?;
    let receipt = AdmissionCleanupAction::pending(
        &committed,
        AdmissionCleanupActionKind::TerminalReceipt,
        &serde_json::json!({"terminal": "completed"}),
    )?;
    let terminal_commit = || {
        store.compare_and_swap_with_cleanup_action(
            transition(
                &committed,
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted,
                7,
                None,
            ),
            receipt.clone(),
        )
    };
    let terminal = applied(terminal_commit()?)?;
    assert_eq!(
        terminal_commit()?,
        AdmissionOperationCasOutcome::Conflict(terminal.clone())
    );

    let claimed =
        match store.claim_cleanup_action(receipt.action_id(), "outbox-worker", 100, 200)? {
            AdmissionCleanupActionClaimOutcome::Claimed(claimed) => claimed,
            other => return Err(format!("terminal receipt was not claimable: {other:?}").into()),
        };
    let acknowledged = store.acknowledge_cleanup_action(
        claimed.action_id(),
        claimed.version(),
        "outbox-worker",
    )?;

    assert!(
        matches!(&acknowledged, AdmissionCleanupActionCasOutcome::Applied(action)
            if action.state() == AdmissionCleanupActionState::Completed),
        "{acknowledged:?}"
    );
    assert_eq!(store.load(terminal.operation_id())?, Some(terminal));
    assert_eq!(
        store.list_operations_with_pending_cleanup_action(
            AdmissionOperationKind::GovernedActiveResponse,
            AdmissionCleanupActionKind::TerminalReceipt,
            PAGE_LIMIT,
        )?,
        Vec::<String>::new()
    );
    Ok(())
}

#[test]
fn pending_receipt_traversal_reaches_a_later_outbox_past_failing_heads() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let mut heads = Vec::with_capacity(PAGE_LIMIT);
    for index in 0..PAGE_LIMIT {
        heads.push(terminal_with_pending_receipt(
            &store,
            &format!("failing-head-{index}"),
            AdmissionOperationState::Completed,
            AdmissionDispatchState::EffectCompleted,
            None,
        )?);
    }
    heads.sort_unstable_by(|left, right| left.0.operation_id().cmp(right.0.operation_id()));
    let last_head = heads
        .last()
        .map(|(operation, _)| operation.operation_id().to_string())
        .ok_or("failing heads")?;
    let tail_request = (0..100_000)
        .map(|index| format!("healthy-tail-{index}"))
        .find(|request_id| {
            governed_response(request_id)
                .is_ok_and(|operation| operation.operation_id() > last_head.as_str())
        })
        .ok_or("healthy tail after every failing head")?;
    let (tail, tail_receipt) = terminal_with_pending_receipt(
        &store,
        &tail_request,
        AdmissionOperationState::Completed,
        AdmissionDispatchState::EffectCompleted,
        None,
    )?;

    let mut cursor: Option<String> = None;
    let mut visited = Vec::new();
    for pass in 0..PAGE_LIMIT + 2 {
        let page = pending_receipt_page(&store, cursor.as_deref(), PAGE_LIMIT)?;
        if page.is_empty() {
            break;
        }
        let now = 1_000 * (u64::try_from(pass)? + 1);
        for operation_id in &page {
            let receipt = if operation_id == tail.operation_id() {
                &tail_receipt
            } else {
                heads
                    .iter()
                    .find(|(operation, _)| operation.operation_id() == operation_id)
                    .map(|(_, receipt)| receipt)
                    .ok_or("listed operation is neither a head nor the tail")?
            };
            let claimed = match store.claim_cleanup_action(
                receipt.action_id(),
                "outbox-worker",
                now,
                now + 100,
            )? {
                AdmissionCleanupActionClaimOutcome::Claimed(claimed) => claimed,
                other => return Err(format!("receipt was not claimable: {other:?}").into()),
            };
            if operation_id == tail.operation_id() {
                store.acknowledge_cleanup_action(
                    claimed.action_id(),
                    claimed.version(),
                    "outbox-worker",
                )?;
            } else {
                store.abandon_cleanup_action(
                    claimed.action_id(),
                    claimed.version(),
                    "outbox-worker",
                    "receipt persistence refused".to_string(),
                )?;
            }
        }
        cursor = page.last().cloned();
        visited.extend(page);
    }

    let mut expected = heads
        .iter()
        .map(|(operation, _)| operation.operation_id().to_string())
        .collect::<Vec<_>>();
    expected.push(tail.operation_id().to_string());
    assert_eq!(visited, expected);
    assert_eq!(
        receipt_state(&store, tail.operation_id())?,
        AdmissionCleanupActionState::Completed
    );
    for (head, _) in &heads {
        assert_eq!(
            receipt_state(&store, head.operation_id())?,
            AdmissionCleanupActionState::Pending
        );
    }
    Ok(())
}

#[test]
fn request_id_owner_refuses_a_different_operation_identity() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let owner = tool_dispatch("capability-1", &"22".repeat(32), "hold-owner-a")?;
    store.create_prepared(owner.clone())?;

    for contender in [
        tool_dispatch("capability-1", &"99".repeat(32), "hold-owner-b")?,
        tool_dispatch("capability-2", &"22".repeat(32), "hold-owner-c")?,
    ] {
        assert_ne!(contender.operation_id(), owner.operation_id());
        assert_eq!(contender.request_id(), owner.request_id());
        let created = store.create_prepared(contender.clone());
        assert!(
            matches!(&created, Err(AdmissionOperationError::Conflict(message)) if message == REQUEST_OWNER_CONFLICT),
            "{created:?}"
        );
        assert_eq!(store.load(contender.operation_id())?, None);
    }
    assert_eq!(
        store.load_by_request_id(AdmissionOperationKind::ToolDispatch, "request-owner", 4)?,
        vec![owner]
    );
    Ok(())
}

#[test]
fn out_of_band_terminal_receipt_insert_is_refused() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let committed = dispatch_committed(&store, "stray-terminal-receipt")?;
    let stray = AdmissionCleanupAction::pending(
        &committed,
        AdmissionCleanupActionKind::TerminalReceipt,
        &serde_json::json!({"terminal": "stray"}),
    )?;

    let inserted = store.create_cleanup_action(stray);

    assert!(
        matches!(&inserted, Err(AdmissionOperationError::Invalid(message)) if message == OUT_OF_BAND_TERMINAL_RECEIPT),
        "{inserted:?}"
    );
    assert_eq!(
        store.load_cleanup_actions(committed.operation_id())?,
        Vec::new()
    );
    assert_eq!(store.load(committed.operation_id())?, Some(committed));
    Ok(())
}

#[test]
fn out_of_band_terminal_receipt_cannot_wedge_the_atomic_terminal_commit() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let committed = dispatch_committed(&store, "wedged-terminal-commit")?;
    let stray = AdmissionCleanupAction::pending(
        &committed,
        AdmissionCleanupActionKind::TerminalReceipt,
        &serde_json::json!({"terminal": "stray"}),
    )?;
    let genuine = AdmissionCleanupAction::pending(
        &committed,
        AdmissionCleanupActionKind::TerminalReceipt,
        &serde_json::json!({"terminal": "completed"}),
    )?;

    let inserted = store.create_cleanup_action(stray);
    let listed_before_terminal = store.list_operations_with_pending_cleanup_action(
        AdmissionOperationKind::GovernedActiveResponse,
        AdmissionCleanupActionKind::TerminalReceipt,
        PAGE_LIMIT,
    )?;
    let terminal_state = store
        .compare_and_swap_with_cleanup_action(
            transition(
                &committed,
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted,
                7,
                None,
            ),
            genuine.clone(),
        )
        .map(|outcome| match outcome {
            AdmissionOperationCasOutcome::Applied(operation) => Some(operation.state()),
            _ => None,
        })
        .map_err(|error| error.to_string());

    assert_eq!(
        (listed_before_terminal, terminal_state),
        (Vec::new(), Ok(Some(AdmissionOperationState::Completed)))
    );
    assert!(
        matches!(&inserted, Err(AdmissionOperationError::Invalid(message)) if message == OUT_OF_BAND_TERMINAL_RECEIPT),
        "{inserted:?}"
    );
    assert_eq!(
        store.load_cleanup_actions(committed.operation_id())?,
        vec![genuine]
    );
    Ok(())
}

#[test]
fn pending_receipt_page_lists_only_unfinished_terminal_outboxes_after_the_cursor() -> TestResult {
    let store = InMemoryAdmissionOperationStore::new();
    let prepared = governed_response("compensated-page")?;
    store.create_prepared(prepared.clone())?;
    let receipt = AdmissionCleanupAction::pending(
        &prepared,
        AdmissionCleanupActionKind::TerminalReceipt,
        &serde_json::json!({"terminal": "compensated_before_dispatch"}),
    )?;
    let compensation_pending = applied(store.compare_and_swap_with_cleanup_action(
        transition(
            &prepared,
            AdmissionOperationState::CompensationPending,
            AdmissionDispatchState::NotStarted,
            7,
            Some("deny"),
        ),
        receipt.clone(),
    )?)?;
    assert_eq!(
        pending_receipt_page(&store, None, PAGE_LIMIT)?,
        Vec::<String>::new()
    );

    let compensated = applied(store.compare_and_swap_with_cleanup_action(
        transition(
            &compensation_pending,
            AdmissionOperationState::CompensatedBeforeDispatch,
            AdmissionDispatchState::NotStarted,
            7,
            Some("deny"),
        ),
        receipt.clone(),
    )?)?;
    let operation_id = compensated.operation_id().to_string();
    assert_eq!(
        pending_receipt_page(&store, None, PAGE_LIMIT)?,
        vec![operation_id.clone()]
    );
    assert_eq!(
        pending_receipt_page(&store, Some(&operation_id), PAGE_LIMIT)?,
        Vec::<String>::new()
    );
    assert_eq!(pending_receipt_page(&store, None, 0)?, Vec::<String>::new());
    assert_eq!(
        store.list_operations_with_pending_cleanup_action_page(
            AdmissionOperationKind::ToolDispatch,
            AdmissionCleanupActionKind::TerminalReceipt,
            None,
            PAGE_LIMIT,
        )?,
        Vec::<String>::new()
    );

    let claimed =
        match store.claim_cleanup_action(receipt.action_id(), "outbox-worker", 100, 200)? {
            AdmissionCleanupActionClaimOutcome::Claimed(claimed) => claimed,
            other => return Err(format!("terminal receipt was not claimable: {other:?}").into()),
        };
    store.acknowledge_cleanup_action(claimed.action_id(), claimed.version(), "outbox-worker")?;
    assert_eq!(
        pending_receipt_page(&store, None, PAGE_LIMIT)?,
        Vec::<String>::new()
    );
    Ok(())
}
