// The settlement-observer outcome is routed into the retry/dead-letter
// machinery, never dropped: a retryable outcome persists a bounded attempt
// row, an accepted outcome clears it, and a permanent outcome lands exactly
// one dead-letter row.

const RECORDING_SETTLEMENT_STORAGE_IDENTITY_BYTE: u8 = 0x31;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordingOutboxState {
    Pending,
    Claimed,
    Routing,
    Completed,
}

struct RecordingOutboxRow {
    finalized_at: u64,
    state: RecordingOutboxState,
    claim_token: Option<String>,
    claim_deadline_unix_ms: Option<u64>,
    version: u64,
    staged_status_json: Option<String>,
}

#[derive(Default)]
struct RecordingReceiptState {
    receipts: std::collections::HashMap<String, chio_core::receipt::body::ChioReceipt>,
    outbox: std::collections::HashMap<String, RecordingOutboxRow>,
}

#[derive(Default)]
struct RecordingReceiptStore {
    state: std::sync::Mutex<RecordingReceiptState>,
}

impl crate::ReceiptStore for RecordingReceiptStore {
    fn append_chio_receipt(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<(), crate::ReceiptStoreError> {
        self.state
            .lock()
            .unwrap()
            .receipts
            .insert(receipt.id.clone(), receipt.clone());
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), crate::ReceiptStoreError> {
        Ok(())
    }

    fn durable_storage_identity(
        &self,
    ) -> Result<Option<chio_core::Hash>, crate::ReceiptStoreError> {
        Ok(Some(chio_core::Hash::from_bytes(
            [RECORDING_SETTLEMENT_STORAGE_IDENTITY_BYTE; 32],
        )))
    }

    fn supports_authoritative_chio_receipt_lookup(&self) -> bool {
        true
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<chio_core::receipt::body::ChioReceipt>, crate::ReceiptStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .receipts
            .get(receipt_id)
            .cloned())
    }

    fn append_chio_receipt_with_settlement_observer_outbox_with_timeout(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
        _budget: std::time::Duration,
    ) -> Result<Option<u64>, crate::ReceiptStoreError> {
        let mut state = self.state.lock().unwrap();
        state.receipts.insert(receipt.id.clone(), receipt.clone());
        state
            .outbox
            .entry(receipt.id.clone())
            .or_insert_with(|| RecordingOutboxRow {
                finalized_at: receipt.timestamp,
                state: RecordingOutboxState::Pending,
                claim_token: None,
                claim_deadline_unix_ms: None,
                version: 0,
                staged_status_json: None,
            });
        Ok(Some(1))
    }

    fn supports_durable_settlement_observer_outbox(&self) -> bool {
        true
    }

    fn list_settlement_observer_outbox_receipt_ids(
        &self,
        now_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<String>, crate::ReceiptStoreError> {
        let state = self.state.lock().unwrap();
        let mut due = state
            .outbox
            .iter()
            .filter(|(_, row)| {
                row.state == RecordingOutboxState::Pending
                    || (matches!(
                        row.state,
                        RecordingOutboxState::Claimed | RecordingOutboxState::Routing
                    ) && row
                        .claim_deadline_unix_ms
                        .is_some_and(|deadline| deadline <= now_unix_ms))
            })
            .map(|(receipt_id, row)| (row.finalized_at, receipt_id.clone()))
            .collect::<Vec<_>>();
        due.sort();
        due.truncate(limit);
        Ok(due
            .into_iter()
            .map(|(_, receipt_id)| receipt_id)
            .collect())
    }

    fn count_unfinished_settlement_observer_outbox(
        &self,
    ) -> Result<u64, crate::ReceiptStoreError> {
        let count = self
            .state
            .lock()
            .unwrap()
            .outbox
            .values()
            .filter(|row| row.state != RecordingOutboxState::Completed)
            .count();
        u64::try_from(count).map_err(|_| {
            crate::ReceiptStoreError::Conflict(
                "test settlement outbox count exceeds u64".to_string(),
            )
        })
    }

    fn claim_settlement_observer_outbox(
        &self,
        receipt_id: &str,
        claim_token: &str,
        now_unix_ms: u64,
        claim_deadline_unix_ms: u64,
    ) -> Result<crate::SettlementObserverOutboxClaimOutcome, crate::ReceiptStoreError> {
        let mut state = self.state.lock().unwrap();
        let Some(row) = state.outbox.get_mut(receipt_id) else {
            return Ok(crate::SettlementObserverOutboxClaimOutcome::Missing);
        };
        if row.state == RecordingOutboxState::Completed {
            return Ok(crate::SettlementObserverOutboxClaimOutcome::Completed);
        }
        let reclaimable = row.state == RecordingOutboxState::Pending
            || (matches!(
                row.state,
                RecordingOutboxState::Claimed | RecordingOutboxState::Routing
            ) && row
                .claim_deadline_unix_ms
                .is_some_and(|deadline| deadline <= now_unix_ms));
        if !reclaimable {
            return Ok(crate::SettlementObserverOutboxClaimOutcome::Busy);
        }
        if row.state != RecordingOutboxState::Routing {
            row.state = RecordingOutboxState::Claimed;
        }
        row.claim_token = Some(claim_token.to_string());
        row.claim_deadline_unix_ms = Some(claim_deadline_unix_ms);
        row.version = row.version.saturating_add(1);
        Ok(crate::SettlementObserverOutboxClaimOutcome::Claimed(
            crate::SettlementObserverOutboxLease {
                receipt_id: receipt_id.to_string(),
                finalized_at: row.finalized_at,
                claim_token: claim_token.to_string(),
                claim_deadline_unix_ms,
                version: row.version,
                staged_status_json: row.staged_status_json.clone(),
            },
        ))
    }

    fn stage_settlement_observer_outbox_status(
        &self,
        receipt_id: &str,
        expected_version: u64,
        claim_token: &str,
        status_json: &str,
    ) -> Result<Option<crate::SettlementObserverOutboxLease>, crate::ReceiptStoreError> {
        let mut state = self.state.lock().unwrap();
        let Some(row) = state.outbox.get_mut(receipt_id) else {
            return Ok(None);
        };
        if row.state != RecordingOutboxState::Claimed
            || row.version != expected_version
            || row.claim_token.as_deref() != Some(claim_token)
        {
            return Ok(None);
        }
        row.state = RecordingOutboxState::Routing;
        row.version = row.version.saturating_add(1);
        row.staged_status_json = Some(status_json.to_string());
        Ok(Some(crate::SettlementObserverOutboxLease {
            receipt_id: receipt_id.to_string(),
            finalized_at: row.finalized_at,
            claim_token: claim_token.to_string(),
            claim_deadline_unix_ms: row.claim_deadline_unix_ms.unwrap_or(0),
            version: row.version,
            staged_status_json: row.staged_status_json.clone(),
        }))
    }

    fn acknowledge_settlement_observer_outbox(
        &self,
        receipt_id: &str,
        expected_version: u64,
        claim_token: &str,
    ) -> Result<bool, crate::ReceiptStoreError> {
        let mut state = self.state.lock().unwrap();
        let Some(row) = state.outbox.get_mut(receipt_id) else {
            return Ok(false);
        };
        if row.state != RecordingOutboxState::Routing
            || row.version != expected_version
            || row.claim_token.as_deref() != Some(claim_token)
        {
            return Ok(false);
        }
        row.state = RecordingOutboxState::Completed;
        row.claim_token = None;
        row.claim_deadline_unix_ms = None;
        row.staged_status_json = None;
        row.version = row.version.saturating_add(1);
        Ok(true)
    }

    fn abandon_settlement_observer_outbox(
        &self,
        receipt_id: &str,
        expected_version: u64,
        claim_token: &str,
        _last_error: &str,
    ) -> Result<bool, crate::ReceiptStoreError> {
        let mut state = self.state.lock().unwrap();
        let Some(row) = state.outbox.get_mut(receipt_id) else {
            return Ok(false);
        };
        if !matches!(
            row.state,
            RecordingOutboxState::Claimed | RecordingOutboxState::Routing
        ) || row.version != expected_version
            || row.claim_token.as_deref() != Some(claim_token)
        {
            return Ok(false);
        }
        if row.state == RecordingOutboxState::Routing {
            row.claim_deadline_unix_ms = Some(0);
        } else {
            row.state = RecordingOutboxState::Pending;
            row.claim_token = None;
            row.claim_deadline_unix_ms = None;
        }
        row.version = row.version.saturating_add(1);
        Ok(true)
    }
}

#[derive(Default)]
struct RecordingRetryStore {
    attempts: std::sync::Mutex<
        std::collections::HashMap<String, crate::settlement_retry::SettleAttemptRecord>,
    >,
    dead_letters: std::sync::Mutex<Vec<chio_settle::DeadLetterRecord>>,
}

impl RecordingRetryStore {
    fn attempt(&self, receipt_id: &str) -> Option<crate::settlement_retry::SettleAttemptRecord> {
        self.attempts.lock().unwrap().get(receipt_id).cloned()
    }

    fn dead_letter_count(&self) -> usize {
        self.dead_letters.lock().unwrap().len()
    }
}

impl crate::settlement_retry::SettlementRetryStore for RecordingRetryStore {
    fn supports_durable_settlement_retry(&self) -> bool {
        true
    }

    fn durable_storage_identity(
        &self,
    ) -> Result<Option<chio_core::Hash>, crate::settlement_retry::SettlementRetryError> {
        Ok(Some(chio_core::Hash::from_bytes(
            [RECORDING_SETTLEMENT_STORAGE_IDENTITY_BYTE; 32],
        )))
    }

    fn load_attempt(
        &self,
        receipt_id: &str,
    ) -> Result<
        Option<crate::settlement_retry::SettleAttemptRecord>,
        crate::settlement_retry::SettlementRetryError,
    > {
        Ok(self.attempt(receipt_id))
    }

    fn upsert_attempt(
        &self,
        record: &crate::settlement_retry::SettleAttemptRecord,
    ) -> Result<(), crate::settlement_retry::SettlementRetryError> {
        self.attempts
            .lock()
            .unwrap()
            .insert(record.receipt_id.clone(), record.clone());
        Ok(())
    }

    fn insert_observer_attempt_if_absent(
        &self,
        record: &crate::settlement_retry::SettleAttemptRecord,
    ) -> Result<bool, crate::settlement_retry::SettlementRetryError> {
        let mut attempts = self.attempts.lock().unwrap();
        if let Some(existing) = attempts.get(&record.receipt_id) {
            if existing.finalized_at != record.finalized_at {
                return Err(crate::settlement_retry::SettlementRetryError::Conflict(
                    "settlement observer finalized_at changed".to_string(),
                ));
            }
            return Ok(false);
        }
        attempts.insert(record.receipt_id.clone(), record.clone());
        Ok(true)
    }

    fn clear_attempt(
        &self,
        receipt_id: &str,
    ) -> Result<(), crate::settlement_retry::SettlementRetryError> {
        self.attempts.lock().unwrap().remove(receipt_id);
        Ok(())
    }

    fn insert_dead_letter(
        &self,
        record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, crate::settlement_retry::SettlementRetryError> {
        let mut letters = self.dead_letters.lock().unwrap();
        if letters
            .iter()
            .any(|existing| existing.receipt_id == record.receipt_id)
        {
            return Ok(false);
        }
        letters.push(record.clone());
        Ok(true)
    }

    fn due_attempts(
        &self,
        now_unix_secs: u64,
        limit: usize,
    ) -> Result<
        Vec<crate::settlement_retry::SettleAttemptRecord>,
        crate::settlement_retry::SettlementRetryError,
    > {
        let mut due: Vec<_> = self
            .attempts
            .lock()
            .unwrap()
            .values()
            .filter(|record| record.next_visible_at <= now_unix_secs)
            .cloned()
            .collect();
        due.sort_by_key(|record| record.next_visible_at);
        due.truncate(limit);
        Ok(due)
    }
}

struct RetryableSettlementHook;

impl chio_settle::SettlementHook for RetryableSettlementHook {
    fn supports_receipt_id_idempotency(&self) -> bool {
        true
    }

    fn observe(
        &self,
        _observation: &chio_settle::SettlementObservation,
        _idempotency_key: &chio_settle::SettlementIdempotencyKey,
    ) -> Result<chio_settle::SettlementOutcome, chio_settle::SettlementHookError> {
        Ok(chio_settle::SettlementOutcome::retryable(
            "rail temporarily unavailable credential-é-SEED-retry".into(),
        ))
    }
}

struct FailingSettlementHook;

impl chio_settle::SettlementHook for FailingSettlementHook {
    fn supports_receipt_id_idempotency(&self) -> bool {
        true
    }

    fn observe(
        &self,
        _observation: &chio_settle::SettlementObservation,
        _idempotency_key: &chio_settle::SettlementIdempotencyKey,
    ) -> Result<chio_settle::SettlementOutcome, chio_settle::SettlementHookError> {
        Err(chio_settle::SettlementHookError::Transient(
            "settlement rpc endpoint unreachable credential-é-SEED-hook".to_string(),
        ))
    }
}

struct RoutingCountingSettlementHook {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    transcript: &'static str,
}

impl chio_settle::SettlementHook for RoutingCountingSettlementHook {
    fn supports_receipt_id_idempotency(&self) -> bool {
        true
    }

    fn observe(
        &self,
        _observation: &chio_settle::SettlementObservation,
        _idempotency_key: &chio_settle::SettlementIdempotencyKey,
    ) -> Result<chio_settle::SettlementOutcome, chio_settle::SettlementHookError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(chio_settle::SettlementOutcome::accepted(self.transcript))
    }
}

struct BlockingSettlementHook {
    calls: std::sync::atomic::AtomicUsize,
    entered: std::sync::Mutex<Option<std::sync::mpsc::Sender<std::thread::ThreadId>>>,
    released: std::sync::Mutex<bool>,
    release_signal: std::sync::Condvar,
}

impl BlockingSettlementHook {
    fn new(entered: std::sync::mpsc::Sender<std::thread::ThreadId>) -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            entered: std::sync::Mutex::new(Some(entered)),
            released: std::sync::Mutex::new(false),
            release_signal: std::sync::Condvar::new(),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release_signal.notify_all();
    }
}

impl chio_settle::SettlementHook for BlockingSettlementHook {
    fn supports_receipt_id_idempotency(&self) -> bool {
        true
    }

    fn observe(
        &self,
        _observation: &chio_settle::SettlementObservation,
        _idempotency_key: &chio_settle::SettlementIdempotencyKey,
    ) -> Result<chio_settle::SettlementOutcome, chio_settle::SettlementHookError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(std::thread::current().id());
        }
        let released = self.released.lock().unwrap();
        let _released = self
            .release_signal
            .wait_while(released, |released| !*released)
            .unwrap();
        Ok(chio_settle::SettlementOutcome::accepted(
            "blocking-hook-accepted",
        ))
    }
}

struct BlockingSettlementHookRelease(std::sync::Arc<BlockingSettlementHook>);

impl Drop for BlockingSettlementHookRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

pub(super) struct ReplacementReceiptStore {
    identity: chio_core::Hash,
    inventory_calls: std::sync::atomic::AtomicUsize,
}

impl ReplacementReceiptStore {
    pub(super) fn new(identity_byte: u8) -> Self {
        Self {
            identity: chio_core::Hash::from_bytes([identity_byte; 32]),
            inventory_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl crate::ReceiptStore for ReplacementReceiptStore {
    fn append_chio_receipt(
        &self,
        _receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<(), crate::ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), crate::ReceiptStoreError> {
        Ok(())
    }

    fn durable_storage_identity(
        &self,
    ) -> Result<Option<chio_core::Hash>, crate::ReceiptStoreError> {
        Ok(Some(self.identity))
    }

    fn supports_authoritative_chio_receipt_lookup(&self) -> bool {
        true
    }

    fn supports_durable_settlement_observer_outbox(&self) -> bool {
        true
    }

    fn list_settlement_observer_outbox_receipt_ids(
        &self,
        _now_unix_ms: u64,
        _limit: usize,
    ) -> Result<Vec<String>, crate::ReceiptStoreError> {
        self.inventory_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Vec::new())
    }

    fn count_unfinished_settlement_observer_outbox(
        &self,
    ) -> Result<u64, crate::ReceiptStoreError> {
        Ok(0)
    }

    fn supports_dispatch_intent_recovery(&self) -> bool {
        true
    }
}

pub(super) struct ReplacementRetryStore {
    identity: chio_core::Hash,
}

pub(super) fn install_empty_durable_settlement_stores(
    kernel: &mut ChioKernel,
    identity_byte: u8,
) {
    kernel
        .set_settlement_retry_store(std::sync::Arc::new(ReplacementRetryStore {
            identity: chio_core::Hash::from_bytes([identity_byte; 32]),
        }))
        .expect("durable retry store");
    kernel
        .try_set_receipt_store_handle(std::sync::Arc::new(ReplacementReceiptStore::new(
            identity_byte,
        )))
        .expect("durable receipt store");
}

impl crate::settlement_retry::SettlementRetryStore for ReplacementRetryStore {
    fn supports_durable_settlement_retry(&self) -> bool {
        true
    }

    fn durable_storage_identity(
        &self,
    ) -> Result<Option<chio_core::Hash>, crate::settlement_retry::SettlementRetryError> {
        Ok(Some(self.identity))
    }

    fn load_attempt(
        &self,
        _receipt_id: &str,
    ) -> Result<
        Option<crate::settlement_retry::SettleAttemptRecord>,
        crate::settlement_retry::SettlementRetryError,
    > {
        Ok(None)
    }

    fn upsert_attempt(
        &self,
        _record: &crate::settlement_retry::SettleAttemptRecord,
    ) -> Result<(), crate::settlement_retry::SettlementRetryError> {
        Ok(())
    }

    fn insert_observer_attempt_if_absent(
        &self,
        _record: &crate::settlement_retry::SettleAttemptRecord,
    ) -> Result<bool, crate::settlement_retry::SettlementRetryError> {
        Ok(true)
    }

    fn clear_attempt(
        &self,
        _receipt_id: &str,
    ) -> Result<(), crate::settlement_retry::SettlementRetryError> {
        Ok(())
    }

    fn insert_dead_letter(
        &self,
        _record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, crate::settlement_retry::SettlementRetryError> {
        Ok(true)
    }

    fn due_attempts(
        &self,
        _now_unix_secs: u64,
        _limit: usize,
    ) -> Result<
        Vec<crate::settlement_retry::SettleAttemptRecord>,
        crate::settlement_retry::SettlementRetryError,
    > {
        Ok(Vec::new())
    }
}

fn monetary_kernel_with_retry_store() -> (
    ChioKernel,
    std::sync::Arc<RecordingRetryStore>,
    CapabilityToken,
    Keypair,
) {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "settlement-retry");
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    kernel
        .try_set_receipt_store_handle(std::sync::Arc::new(RecordingReceiptStore::default()))
        .expect("durable receipt store");
    let retry_store = std::sync::Arc::new(RecordingRetryStore::default());
    kernel
        .set_settlement_retry_store(retry_store.clone())
        .unwrap();
    kernel
        .set_settlement_observer(std::sync::Arc::new(RetryableSettlementHook))
        .expect("observer install succeeds once the retry store is present");
    kernel.settlement_observer_recovery = None;

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    (kernel, retry_store, cap, agent_kp)
}

fn priced_request(request_id: &str, cap: &CapabilityToken, agent: &Keypair) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({}),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

fn unfinished_settlement_observer_rows(store: &RecordingReceiptStore) -> u64 {
    crate::ReceiptStore::count_unfinished_settlement_observer_outbox(store).unwrap()
}

fn wait_for_settlement_condition(message: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "{message}");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn observer_install_without_a_retry_store_is_rejected() {
    let mut kernel = make_kernel(make_monetary_config());

    let error = kernel
        .set_settlement_observer(std::sync::Arc::new(RetryableSettlementHook))
        .expect_err("an observer without a durable retry store must be rejected at wiring time");
    assert!(
        matches!(error, KernelBuildError::MissingSettlementRetryStore),
        "the rejection must name the missing retry store: {error}"
    );
    assert!(
        error.to_string().contains("set_settlement_retry_store"),
        "the error must tell the embedder which call is missing: {error}"
    );
    assert!(
        kernel.settlement_observer().is_none(),
        "a rejected install must leave no observer wired"
    );

    // The same install succeeds once the durable sink is present.
    kernel
        .try_set_receipt_store_handle(std::sync::Arc::new(RecordingReceiptStore::default()))
        .expect("durable receipt store");
    kernel
        .set_settlement_retry_store(std::sync::Arc::new(RecordingRetryStore::default()))
        .unwrap();
    kernel
        .set_settlement_observer(std::sync::Arc::new(RetryableSettlementHook))
        .expect("observer install succeeds once the retry store is present");
    assert!(kernel.settlement_observer().is_some());
}

#[test]
fn second_settlement_observer_install_preserves_original_hook_and_worker() {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "settlement-observer-replacement");
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let receipt_store = std::sync::Arc::new(RecordingReceiptStore::default());
    kernel
        .try_set_receipt_store_handle(receipt_store.clone())
        .expect("durable receipt store");
    kernel
        .set_settlement_retry_store(std::sync::Arc::new(RecordingRetryStore::default()))
        .expect("durable retry store");

    let original_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    kernel
        .set_settlement_observer(std::sync::Arc::new(RoutingCountingSettlementHook {
            calls: original_calls.clone(),
            transcript: "original-observer",
        }))
        .expect("first observer install");
    assert!(kernel.settlement_observer_recovery.is_some());

    let replacement_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let error = kernel
        .set_settlement_observer(std::sync::Arc::new(RoutingCountingSettlementHook {
            calls: replacement_calls.clone(),
            transcript: "replacement-observer",
        }))
        .expect_err("a second observer install must be rejected");
    assert!(matches!(
        error,
        KernelBuildError::SettlementObserverAlreadyInstalled
    ));
    assert!(
        kernel.settlement_observer_recovery.is_some(),
        "the rejected replacement must not take the active recovery worker"
    );

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )
        .unwrap();
    let response = kernel
        .evaluate_tool_call_blocking(&priced_request(
            "req-settle-second-install",
            &cap,
            &agent_kp,
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    wait_for_settlement_condition("original recovery worker did not drain its outbox", || {
        original_calls.load(std::sync::atomic::Ordering::SeqCst) == 1
            && unfinished_settlement_observer_rows(receipt_store.as_ref()) == 0
    });
    assert_eq!(
        replacement_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the rejected replacement hook must never become authoritative"
    );
}

#[test]
fn terminal_receipt_recording_does_not_enter_or_wait_for_hook_on_caller_thread() {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "settlement-terminal-recording");
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let receipt_store = std::sync::Arc::new(RecordingReceiptStore::default());
    kernel
        .try_set_receipt_store_handle(receipt_store.clone())
        .expect("durable receipt store");
    let retry_store = std::sync::Arc::new(RecordingRetryStore::default());
    kernel
        .set_settlement_retry_store(retry_store.clone())
        .expect("durable retry store");

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let hook = std::sync::Arc::new(BlockingSettlementHook::new(entered_tx));
    let _release_hook = BlockingSettlementHookRelease(hook.clone());
    kernel
        .set_settlement_observer(hook.clone())
        .expect("observer install");
    // Stop the polling worker before recording so the assertion cannot pass
    // merely because the worker won a race against an inline delivery path.
    kernel.settlement_observer_recovery = None;

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )
        .unwrap();
    let request = priced_request("req-settle-nonblocking", &cap, &agent_kp);
    let (caller_thread_tx, caller_thread_rx) = std::sync::mpsc::channel();
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let caller = std::thread::spawn(move || {
        caller_thread_tx
            .send(std::thread::current().id())
            .unwrap();
        let result = kernel.evaluate_tool_call_blocking(&request);
        completed_tx.send(()).unwrap();
        (kernel, result)
    });

    let caller_thread_id = caller_thread_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("caller thread did not start");
    if let Err(error) = completed_rx.recv_timeout(std::time::Duration::from_secs(5)) {
        hook.release();
        let _ = caller.join();
        panic!("terminal receipt recording waited for the blocked hook: {error}");
    }
    let (mut kernel, result) = caller.join().unwrap();
    let response = result.expect("tool call succeeds without invoking the observer");

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        hook.calls(),
        0,
        "terminal receipt recording must not enter the observer hook"
    );
    assert!(matches!(
        entered_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert_eq!(
        unfinished_settlement_observer_rows(receipt_store.as_ref()),
        1,
        "the atomic append must leave one durable outbox row"
    );

    let recovery = kernel.spawn_settlement_observer_recovery();
    assert!(recovery.is_some(), "recovery worker must be constructible");
    kernel.settlement_observer_recovery = recovery;
    let observer_thread_id = match entered_rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(thread_id) => thread_id,
        Err(error) => {
            hook.release();
            panic!("background recovery worker did not enter the hook: {error}");
        }
    };
    assert_ne!(
        caller_thread_id, observer_thread_id,
        "the terminal persistence caller must never invoke the observer hook"
    );
    assert_eq!(hook.calls(), 1);
    assert_eq!(
        unfinished_settlement_observer_rows(receipt_store.as_ref()),
        1,
        "the durable outbox remains authoritative while delivery is blocked"
    );

    hook.release();
    wait_for_settlement_condition("background recovery did not acknowledge the outbox", || {
        unfinished_settlement_observer_rows(receipt_store.as_ref()) == 0
    });
    assert_eq!(hook.calls(), 1);
    assert!(retry_store.attempt(&response.receipt.id).is_none());
    assert_eq!(retry_store.dead_letter_count(), 0);
}

#[test]
fn failed_receipt_store_replacement_restores_store_and_worker_handles() {
    let mut kernel = make_kernel(make_monetary_config());
    let old_store = std::sync::Arc::new(ReplacementReceiptStore::new(0x11));
    let old_store_handle: std::sync::Arc<dyn crate::ReceiptStore> = old_store.clone();
    kernel
        .set_settlement_retry_store(std::sync::Arc::new(ReplacementRetryStore {
            identity: chio_core::Hash::from_bytes([0x11; 32]),
        }))
        .expect("retry store");
    kernel
        .try_set_receipt_store_handle(old_store_handle.clone())
        .expect("matching receipt store");
    kernel
        .set_settlement_observer(std::sync::Arc::new(RetryableSettlementHook))
        .expect("observer");
    assert!(kernel.dispatch_intent_recovery.is_some());
    assert!(kernel.settlement_observer_recovery.is_some());

    let replacement = std::sync::Arc::new(ReplacementReceiptStore::new(0x22));
    let replacement_handle: std::sync::Arc<dyn crate::ReceiptStore> = replacement.clone();
    let error = kernel
        .try_set_receipt_store_handle(replacement_handle)
        .expect_err("mismatched commit domain");
    assert!(error.to_string().contains("different commit domains"));
    assert!(std::sync::Arc::ptr_eq(
        kernel.receipt_store.as_ref().expect("restored store"),
        &old_store_handle,
    ));
    assert!(kernel.dispatch_intent_recovery.is_some());
    assert!(kernel.settlement_observer_recovery.is_some());
    assert_eq!(
        replacement
            .inventory_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    let calls_before = old_store
        .inventory_calls
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(kernel.recover_settlement_observer_outboxes().unwrap(), 0);
    assert!(
        old_store
            .inventory_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            > calls_before
    );
}

#[test]
fn retryable_outcome_persists_a_bounded_attempt_row() {
    let (kernel, retry_store, cap, agent_kp) = monetary_kernel_with_retry_store();

    let response = kernel
        .evaluate_tool_call_blocking(&priced_request("req-settle-retry", &cap, &agent_kp))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(kernel.recover_settlement_observer_outboxes().unwrap(), 1);

    let attempt = retry_store
        .attempt(&response.receipt.id)
        .expect("retryable outcome must persist an attempt row");
    assert_eq!(attempt.attempts, 1);
    assert!(
        attempt.next_visible_at > attempt.finalized_at,
        "backoff must push visibility past finalization"
    );
    assert_eq!(
        attempt.last_reason.as_deref(),
        Some("settlement hook requested retry")
    );
    assert!(!attempt
        .last_reason
        .as_deref()
        .unwrap_or_default()
        .contains("credential-é-SEED-retry"));
    assert_eq!(retry_store.dead_letter_count(), 0);
}

#[test]
fn hook_failure_persists_a_bounded_attempt_row() {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "settlement-hook-failure");
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    kernel
        .try_set_receipt_store_handle(std::sync::Arc::new(RecordingReceiptStore::default()))
        .expect("durable receipt store");
    let retry_store = std::sync::Arc::new(RecordingRetryStore::default());
    kernel
        .set_settlement_retry_store(retry_store.clone())
        .unwrap();
    kernel
        .set_settlement_observer(std::sync::Arc::new(FailingSettlementHook))
        .expect("observer install succeeds once the retry store is present");
    kernel.settlement_observer_recovery = None;

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&priced_request("req-settle-hook-err", &cap, &agent_kp))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(kernel.recover_settlement_observer_outboxes().unwrap(), 1);

    // The hook error consumed the same bounded envelope as a Retryable
    // outcome: a durable attempt row `chio settle drive` picks up, instead
    // of a warn-only log nothing ever retries.
    let attempt = retry_store
        .attempt(&response.receipt.id)
        .expect("a hook failure must persist a settle_attempts row");
    assert_eq!(attempt.attempts, 1);
    assert!(
        attempt.next_visible_at > attempt.finalized_at,
        "backoff must push visibility past finalization"
    );
    assert_eq!(
        attempt.last_reason.as_deref(),
        Some("settlement hook invocation failed")
    );
    assert!(!attempt
        .last_reason
        .as_deref()
        .unwrap_or_default()
        .contains("credential-é-SEED-hook"));
    assert_eq!(retry_store.dead_letter_count(), 0);
}

#[test]
fn accepted_outcome_clears_the_attempt_row() {
    let (kernel, retry_store, cap, agent_kp) = monetary_kernel_with_retry_store();

    let response = kernel
        .evaluate_tool_call_blocking(&priced_request("req-settle-clear", &cap, &agent_kp))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(kernel.recover_settlement_observer_outboxes().unwrap(), 1);
    assert!(retry_store.attempt(&response.receipt.id).is_some());

    kernel
        .classify_and_persist(
            &response.receipt,
            &chio_settle::SettlementOutcome::accepted("ts-clear"),
        )
        .expect("accepted outcome resolves");
    assert!(
        retry_store.attempt(&response.receipt.id).is_none(),
        "accepted outcome must clear the bounded envelope"
    );
}

#[test]
fn permanent_outcome_dead_letters_exactly_once() {
    let (kernel, retry_store, cap, agent_kp) = monetary_kernel_with_retry_store();

    let response = kernel
        .evaluate_tool_call_blocking(&priced_request("req-settle-dl", &cap, &agent_kp))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(kernel.recover_settlement_observer_outboxes().unwrap(), 1);

    let outcome = chio_settle::SettlementOutcome::permanent("payee unresolvable".into());
    kernel
        .classify_and_persist(&response.receipt, &outcome)
        .expect("permanent outcome dead-letters");
    kernel
        .classify_and_persist(&response.receipt, &outcome)
        .expect("replayed dead-letter stays idempotent");

    assert_eq!(retry_store.dead_letter_count(), 1);
    assert!(
        retry_store.attempt(&response.receipt.id).is_none(),
        "dead-lettered receipts leave no live attempt row"
    );
}
