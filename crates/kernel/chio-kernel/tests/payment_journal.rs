//! Kernel-surface tests for the durable payment journal: the money path
//! walks HoldPlaced -> Authorized -> Settling -> Settled -> Closed around
//! the rail calls, and boot reconciliation resolves every incomplete row to
//! exactly one terminal outcome.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::CapabilityToken,
    };
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, DispatchIntentJournalMode, KernelConfig, KernelError, NestedFlowBridge,
        ToolCallRequest, ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};

    pub fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nonce}.sqlite3", std::process::id()))
    }

    /// Payment rail that settles locally and counts every capture/release so
    /// tests can prove money moved at most once. `settlement_state` answers
    /// like the in-tree prepaid rails (funds move at authorize) unless a
    /// test scripts a different answer for a specific reference, so crash-
    /// window scenarios other than "already settled" stay reachable.
    pub struct CountingRail {
        pub captures: AtomicUsize,
        pub releases: AtomicUsize,
        settlement_state_script:
            Mutex<HashMap<String, Result<chio_kernel::RailSettlementState, String>>>,
    }

    impl CountingRail {
        pub fn new() -> Self {
            Self {
                captures: AtomicUsize::new(0),
                releases: AtomicUsize::new(0),
                settlement_state_script: Mutex::new(HashMap::new()),
            }
        }

        /// Script a specific `settlement_state` answer for one reference,
        /// overriding the default "prepaid rail always settled" response.
        pub fn script_settlement_state(
            &self,
            reference: &str,
            state: chio_kernel::RailSettlementState,
        ) {
            self.settlement_state_script
                .lock()
                .expect("script lock")
                .insert(reference.to_string(), Ok(state));
        }

        /// Script `settlement_state` to fail for one reference, simulating a
        /// rail that cannot say whether funds moved.
        pub fn script_settlement_state_error(&self, reference: &str, detail: &str) {
            self.settlement_state_script
                .lock()
                .expect("script lock")
                .insert(reference.to_string(), Err(detail.to_string()));
        }
    }

    impl chio_kernel::PaymentAdapter for CountingRail {
        fn rail_id(&self) -> &str {
            "x402"
        }

        fn authorize(
            &self,
            request: &chio_kernel::PaymentAuthorizeRequest,
        ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
            Ok(chio_kernel::PaymentAuthorization {
                authorization_id: format!("auth-{}", request.reference),
                settled: false,
                metadata: serde_json::json!({}),
            })
        }

        fn capture(
            &self,
            authorization_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.captures
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(chio_kernel::PaymentResult {
                transaction_id: format!("txn-{authorization_id}"),
                settlement_status: chio_kernel::RailSettlementStatus::Settled,
                metadata: serde_json::json!({}),
            })
        }

        fn release(
            &self,
            authorization_id: &str,
            _reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.releases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(chio_kernel::PaymentResult {
                transaction_id: authorization_id.to_string(),
                settlement_status: chio_kernel::RailSettlementStatus::Released,
                metadata: serde_json::json!({}),
            })
        }

        fn refund(
            &self,
            transaction_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            Ok(chio_kernel::PaymentResult {
                transaction_id: transaction_id.to_string(),
                settlement_status: chio_kernel::RailSettlementStatus::Refunded,
                metadata: serde_json::json!({}),
            })
        }

        fn settlement_state(
            &self,
            reference: &str,
            authorization_id: Option<&str>,
        ) -> Result<chio_kernel::RailSettlementState, chio_kernel::PaymentError> {
            if let Some(scripted) = self
                .settlement_state_script
                .lock()
                .expect("script lock")
                .get(reference)
            {
                return scripted
                    .clone()
                    .map_err(chio_kernel::PaymentError::Unavailable);
            }
            let authorization_id = authorization_id
                .map(str::to_string)
                .unwrap_or_else(|| format!("auth-{reference}"));
            Ok(chio_kernel::RailSettlementState::Settled {
                authorization_id: authorization_id.clone(),
                result: chio_kernel::PaymentResult {
                    transaction_id: authorization_id,
                    settlement_status: chio_kernel::RailSettlementStatus::Settled,
                    metadata: serde_json::json!({}),
                },
            })
        }
    }

    /// Tool server that probes the payment journal from INSIDE `invoke`,
    /// capturing the incomplete rows at the moment the tool effect runs. The
    /// authorized row must be durable before dispatch.
    pub struct JournalProbeServer {
        pub budget_store: Arc<SqliteBudgetStore>,
        pub journal_rows_seen_at_invoke:
            Arc<Mutex<Vec<chio_kernel::payment::PaymentJournalRecord>>>,
        pub reported_cost_units: u64,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for JournalProbeServer {
        fn server_id(&self) -> &str {
            "srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["write_file".to_string()]
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            use chio_kernel::budget_store::BudgetStore;
            let rows = self
                .budget_store
                .list_incomplete_payment_journal(u64::MAX)
                .expect("probe the journal from inside the tool");
            self.journal_rows_seen_at_invoke
                .lock()
                .expect("probe lock")
                .extend(rows);
            Ok(serde_json::json!({ "ok": true }))
        }

        async fn invoke_with_cost(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<(serde_json::Value, Option<chio_kernel::ToolInvocationCost>), KernelError>
        {
            let value = self.invoke(tool_name, arguments, bridge).await?;
            Ok((
                value,
                Some(chio_kernel::ToolInvocationCost {
                    units: self.reported_cost_units,
                    currency: "USD".to_string(),
                    breakdown: None,
                }),
            ))
        }
    }

    pub fn money_config(keypair: Keypair) -> KernelConfig {
        KernelConfig {
            keypair,
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "test-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: DispatchIntentJournalMode::SideEffecting,
        }
    }

    fn money_scope() -> ChioScope {
        let cost = |units: u64| {
            Some(chio_core::capability::scope::MonetaryAmount {
                units,
                currency: "USD".to_string(),
            })
        };
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "write_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: cost(100),
                max_total_cost: cost(10_000),
                dpop_required: None,
            }],
            ..ChioScope::default()
        }
    }

    pub struct MoneyJournalHarness {
        pub kernel: ChioKernel,
        pub budget_store: Arc<SqliteBudgetStore>,
        pub receipt_store: Arc<SqliteReceiptStore>,
        pub rail: Arc<CountingRail>,
        pub capability: CapabilityToken,
        pub journal_rows_seen_at_invoke:
            Arc<Mutex<Vec<chio_kernel::payment::PaymentJournalRecord>>>,
        pub receipt_db_path: std::path::PathBuf,
        pub budget_db_path: std::path::PathBuf,
    }

    /// Payment adapter facade over a shared rail handle, so tests keep a
    /// counter view of the adapter the kernel owns.
    struct SharedRail(Arc<CountingRail>);

    impl chio_kernel::PaymentAdapter for SharedRail {
        fn rail_id(&self) -> &str {
            self.0.rail_id()
        }

        fn authorize(
            &self,
            request: &chio_kernel::PaymentAuthorizeRequest,
        ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
            self.0.authorize(request)
        }

        fn capture(
            &self,
            authorization_id: &str,
            amount_units: u64,
            currency: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.0
                .capture(authorization_id, amount_units, currency, reference)
        }

        fn release(
            &self,
            authorization_id: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.0.release(authorization_id, reference)
        }

        fn refund(
            &self,
            transaction_id: &str,
            amount_units: u64,
            currency: &str,
            reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            self.0
                .refund(transaction_id, amount_units, currency, reference)
        }

        fn settlement_state(
            &self,
            reference: &str,
            authorization_id: Option<&str>,
        ) -> Result<chio_kernel::RailSettlementState, chio_kernel::PaymentError> {
            self.0.settlement_state(reference, authorization_id)
        }
    }

    pub fn money_journal_harness(
        prefix: &str,
        reported_cost_units: u64,
    ) -> Result<MoneyJournalHarness, Box<dyn std::error::Error>> {
        let receipt_db_path = unique_db_path(&format!("{prefix}-receipts"));
        let budget_db_path = unique_db_path(&format!("{prefix}-budget"));
        let receipt_store = Arc::new(SqliteReceiptStore::open(&receipt_db_path)?);
        let budget_store = Arc::new(SqliteBudgetStore::open(&budget_db_path)?);
        let journal_rows_seen_at_invoke = Arc::new(Mutex::new(Vec::new()));
        let rail = Arc::new(CountingRail::new());

        let mut kernel = ChioKernel::new(money_config(Keypair::generate()));
        kernel.register_tool_server(Box::new(JournalProbeServer {
            budget_store: Arc::clone(&budget_store),
            journal_rows_seen_at_invoke: Arc::clone(&journal_rows_seen_at_invoke),
            reported_cost_units,
        }));
        kernel.set_payment_adapter(Box::new(SharedRail(Arc::clone(&rail))));
        kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn chio_kernel::BudgetStore>);
        kernel.set_receipt_store_handle(
            Arc::clone(&receipt_store) as Arc<dyn chio_kernel::ReceiptStore>
        )?;

        let agent_keypair = Keypair::generate();
        let capability =
            kernel.issue_capability(&agent_keypair.public_key(), money_scope(), 300)?;
        Ok(MoneyJournalHarness {
            kernel,
            budget_store,
            receipt_store,
            rail,
            capability,
            journal_rows_seen_at_invoke,
            receipt_db_path,
            budget_db_path,
        })
    }

    impl MoneyJournalHarness {
        pub fn request(&self, request_id: &str) -> ToolCallRequest {
            ToolCallRequest {
                request_id: request_id.to_string(),
                capability: self.capability.clone(),
                tool_name: "write_file".to_string(),
                server_id: "srv".to_string(),
                agent_id: self.capability.subject.to_hex(),
                arguments: serde_json::json!({ "payload": "hello" }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            }
        }

        pub fn cleanup(&self) {
            let _ = std::fs::remove_file(&self.receipt_db_path);
            let _ = std::fs::remove_file(&self.budget_db_path);
        }
    }
}

use chio_kernel::budget_store::BudgetStore;
use chio_kernel::payment::PaymentJournalState;
use chio_kernel::Verdict;

#[test]
fn priced_call_walks_journal_to_closed() -> Result<(), Box<dyn std::error::Error>> {
    let harness = support::money_journal_harness("chio-journal-closed", 75)?;

    let response = harness
        .kernel
        .evaluate_tool_call_blocking(&harness.request("req-P"))?;
    assert!(matches!(response.verdict, Verdict::Allow));

    // From inside the tool, the in-flight row is durable and Authorized with
    // the rail reference already attached: a crash during dispatch leaves a
    // recoverable record.
    let seen = harness
        .journal_rows_seen_at_invoke
        .lock()
        .expect("probe lock");
    let row = seen
        .iter()
        .find(|row| row.request_id == "req-P")
        .expect("the in-flight journal row is visible during dispatch");
    assert_eq!(row.state, PaymentJournalState::Authorized);
    assert_eq!(row.rail, "x402");
    assert_eq!(row.authorization_id.as_deref(), Some("auth-req-P"));
    assert_eq!(row.amount_units, 100);
    assert!(row.hold_id.is_some());
    drop(seen);

    // After the receipt persists, the journal row is closed: no incomplete
    // row remains and the rail captured exactly once.
    let incomplete = harness
        .budget_store
        .list_incomplete_payment_journal(u64::MAX)?;
    assert!(
        incomplete.iter().all(|row| row.request_id != "req-P"),
        "journal row for req-P should be Closed, found {incomplete:?}"
    );
    assert_eq!(
        harness
            .rail
            .captures
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    harness.cleanup();
    Ok(())
}

#[test]
fn boot_reconcile_resolves_every_incomplete_row() -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::payment::{PaymentJournalRecord, PaymentSettleAction, PaymentSettleIntent};

    let harness = support::money_journal_harness("chio-boot-reconcile", 75)?;
    let store = &harness.budget_store;

    // Fabricate the post-crash journal directly, one row per crash window.
    let base = |request_id: &str, state: PaymentJournalState| PaymentJournalRecord {
        request_id: request_id.to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        hold_id: Some(format!("hold-{request_id}")),
        rail: "x402".to_string(),
        authorization_id: Some(format!("auth-{request_id}")),
        transaction_id: None,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state,
        created_at_unix_ms: 1,
    };

    // Crash before or during authorize: no authorization id is durable.
    let mut hold_placed = base("req-hold", PaymentJournalState::HoldPlaced);
    hold_placed.authorization_id = None;
    store.record_payment_journal(&hold_placed)?;

    // Crash after authorize, before any terminal action was committed.
    store.record_payment_journal(&base("req-auth", PaymentJournalState::Authorized))?;

    // Crash inside the rail call: the committed capture is durable.
    store.record_payment_journal(&base("req-settling", PaymentJournalState::HoldPlaced))?;
    store.advance_payment_journal(
        "req-settling",
        PaymentJournalState::HoldPlaced,
        PaymentJournalState::Authorized,
        Some("auth-req-settling"),
        None,
        None,
    )?;
    store.advance_payment_journal(
        "req-settling",
        PaymentJournalState::Authorized,
        PaymentJournalState::Settling,
        None,
        None,
        Some(PaymentSettleIntent {
            action: PaymentSettleAction::Capture,
            amount_units: Some(80),
        }),
    )?;

    // Crash after the money moved, before the receipt closed the row.
    store.record_payment_journal(&base("req-settled", PaymentJournalState::HoldPlaced))?;
    store.advance_payment_journal(
        "req-settled",
        PaymentJournalState::HoldPlaced,
        PaymentJournalState::Authorized,
        Some("auth-req-settled"),
        None,
        None,
    )?;
    store.advance_payment_journal(
        "req-settled",
        PaymentJournalState::Authorized,
        PaymentJournalState::Settling,
        None,
        None,
        Some(PaymentSettleIntent {
            action: PaymentSettleAction::Release,
            amount_units: None,
        }),
    )?;
    store.advance_payment_journal(
        "req-settled",
        PaymentJournalState::Settling,
        PaymentJournalState::Settled,
        None,
        Some("txn-req-settled"),
        None,
    )?;

    // A Settling row with no committed settle action is corrupt: recovery
    // must raise an incident, never guess a capture or release.
    let mut corrupt = base("req-corrupt", PaymentJournalState::Settling);
    corrupt.settle_action = None;
    store.record_payment_journal(&corrupt)?;

    let receipts_before = harness.receipt_store.max_tool_receipt_seq()?;
    let report = harness.kernel.reconcile_payment_journal(0)?;
    let receipts_after = harness.receipt_store.max_tool_receipt_seq()?;
    assert_eq!(
        report.resolved, 4,
        "four rows resolve terminally: {report:?}"
    );
    assert_eq!(
        report.reconcile_failed, 1,
        "the corrupt Settling row raises an incident: {report:?}"
    );

    // Every row reached a terminal state.
    let remaining = store.list_incomplete_payment_journal(u64::MAX)?;
    assert!(
        remaining.is_empty(),
        "unresolved rows after reconcile: {remaining:?}"
    );

    // The committed capture replayed exactly once; req-auth is the only
    // genuine price-free hold and releases. req-hold's rail query reports
    // the prepaid rail's real answer (already settled at authorize), so
    // reconciliation must record it with a receipt rather than release it:
    // releasing here would reverse the local hold and erase the only
    // record of a charge that already happened.
    assert_eq!(
        harness
            .rail
            .captures
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "exactly one capture: the recorded settle action for req-settling"
    );
    assert_eq!(
        harness
            .rail
            .releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only req-auth releases; req-hold reports settled funds and is reconciled with a receipt instead"
    );
    assert_eq!(
        receipts_after - receipts_before,
        3,
        "req-hold, req-settling, and req-settled each emit a reconciliation receipt; \
         req-auth releases and req-corrupt incidents without one"
    );

    // Idempotent: a second pass finds nothing and moves no money.
    let again = harness.kernel.reconcile_payment_journal(0)?;
    assert_eq!(again.resolved, 0);
    assert_eq!(again.reconcile_failed, 0);
    assert_eq!(
        harness
            .rail
            .captures
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "no double capture on a second pass"
    );

    harness.cleanup();
    Ok(())
}

#[test]
fn hold_placed_reconcile_only_releases_a_proven_hold_never_a_settlement(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::payment::PaymentJournalRecord;
    use chio_kernel::{PaymentResult, RailSettlementState, RailSettlementStatus};

    let harness = support::money_journal_harness("chio-holdplaced-branch", 75)?;
    let store = &harness.budget_store;

    // Every row crashed in the same window (HoldPlaced, no durable
    // authorization id): authorize may or may not have fired. Only the
    // rail's answer distinguishes them.
    let base = |request_id: &str| PaymentJournalRecord {
        request_id: request_id.to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        hold_id: Some(format!("hold-{request_id}")),
        rail: "x402".to_string(),
        authorization_id: None,
        transaction_id: None,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 1,
    };

    // A prepaid adapter crashed in the HoldPlaced window after authorize
    // already moved the funds. Releasing here would erase the only record
    // of the charge, so reconciliation must record it instead.
    store.record_payment_journal(&base("req-funds-moved"))?;
    harness.rail.script_settlement_state(
        "req-funds-moved",
        RailSettlementState::Settled {
            authorization_id: "auth-funds-moved".to_string(),
            result: PaymentResult {
                transaction_id: "txn-funds-moved".to_string(),
                settlement_status: RailSettlementStatus::Settled,
                metadata: serde_json::json!({}),
            },
        },
    );

    // A genuine hold-only crash: authorize placed a hold but no funds ever
    // moved. Reconciliation still releases it cleanly.
    store.record_payment_journal(&base("req-hold-only"))?;
    harness.rail.script_settlement_state(
        "req-hold-only",
        RailSettlementState::Held {
            authorization_id: "auth-hold-only".to_string(),
        },
    );

    // The rail cannot say whether funds moved. Never guess: this is an
    // operator incident, not a release.
    store.record_payment_journal(&base("req-unknown"))?;
    harness
        .rail
        .script_settlement_state_error("req-unknown", "rail unreachable during reconcile");

    let receipts_before = harness.receipt_store.max_tool_receipt_seq()?;
    let report = harness.kernel.reconcile_payment_journal(0)?;
    let receipts_after = harness.receipt_store.max_tool_receipt_seq()?;

    assert_eq!(
        report.resolved, 2,
        "req-funds-moved and req-hold-only resolve terminally: {report:?}"
    );
    assert_eq!(
        report.reconcile_failed, 1,
        "req-unknown raises an incident rather than a guess: {report:?}"
    );

    assert_eq!(
        receipts_after - receipts_before,
        1,
        "exactly one reconciliation receipt: req-funds-moved, never req-hold-only or req-unknown"
    );
    assert_eq!(
        harness
            .rail
            .releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the genuine hold-only row releases; a settled or unknown row never does"
    );
    assert_eq!(
        harness
            .rail
            .captures
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the HoldPlaced arm never captures: a settled row is recorded, not replayed"
    );

    // Every row reached a terminal state, including the incident.
    let remaining = store.list_incomplete_payment_journal(u64::MAX)?;
    assert!(
        remaining.is_empty(),
        "unresolved rows after reconcile: {remaining:?}"
    );

    // Idempotent: a second pass finds nothing left to resolve.
    let again = harness.kernel.reconcile_payment_journal(0)?;
    assert_eq!(again.resolved, 0);
    assert_eq!(again.reconcile_failed, 0);

    harness.cleanup();
    Ok(())
}

#[test]
fn monetary_reconciler_resolves_orphaned_intents_through_the_journal(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::payment::PaymentJournalRecord;
    use chio_kernel::receipt_store::{DispatchIntentRecord, SideEffectClass};
    use chio_kernel::MonetaryDispatchIntentReconciler;
    use chio_store_sqlite::SqliteReceiptStore;
    use std::sync::Arc;

    let harness = support::money_journal_harness("chio-monetary-reconciler", 75)?;

    // Fabricate a monetary orphan: an open intent plus its Authorized
    // journal row, exactly the state a crash after authorize leaves. The
    // recording store handle is dropped before reconciliation because an
    // open intent only becomes an orphan once its owning writer is gone;
    // a live writer's in-flight intents are never claimed.
    let intent_db_path = support::unique_db_path("chio-monetary-reconciler-intents");
    {
        let crashed_writer = SqliteReceiptStore::open(&intent_db_path)?;
        crashed_writer.record_dispatch_intent_with_timeout(
            &DispatchIntentRecord {
                request_id: "req-orphan".to_string(),
                capability_id: "cap".to_string(),
                tool_server: "srv".to_string(),
                tool_name: "write_file".to_string(),
                parameter_hash: "hash".to_string(),
                side_effect_class: SideEffectClass::Monetary,
                monetary: true,
                rail: Some("x402".to_string()),
                rail_authorization_id: Some("auth-req-orphan".to_string()),
                tenant_id: None,
                created_at_unix_ms: 1,
            },
            std::time::Duration::from_secs(5),
        )?;
    }
    let receipt_store = Arc::new(SqliteReceiptStore::open(&intent_db_path)?);

    harness
        .budget_store
        .record_payment_journal(&PaymentJournalRecord {
            request_id: "req-orphan".to_string(),
            capability_id: "cap".to_string(),
            grant_index: 0,
            hold_id: Some("hold-req-orphan".to_string()),
            rail: "x402".to_string(),
            authorization_id: Some("auth-req-orphan".to_string()),
            transaction_id: None,
            amount_units: 100,
            settle_action: None,
            settle_amount_units: None,
            currency: "USD".to_string(),
            state: PaymentJournalState::Authorized,
            created_at_unix_ms: 1,
        })?;

    let reconciler = MonetaryDispatchIntentReconciler {
        kernel: &harness.kernel,
    };
    let report = receipt_store.reconcile_dispatch_intents(&reconciler)?;
    assert_eq!(report.open, 1);
    assert_eq!(
        report.replayed, 1,
        "an Authorized orphan releases its hold: funds never moved, safe to replay: {report:?}"
    );

    // The journal row reached a terminal state and the rail hold released.
    assert!(harness
        .budget_store
        .list_incomplete_payment_journal(u64::MAX)?
        .is_empty());
    assert_eq!(
        harness
            .rail
            .releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let _ = std::fs::remove_file(&intent_db_path);
    harness.cleanup();
    Ok(())
}

#[test]
fn hold_sweeper_releases_orphaned_capacity() -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::budget_store::BudgetAuthorizeHoldRequest;

    let mut harness = support::money_journal_harness("chio-hold-sweeper", 75)?;
    // Fabricate an orphaned hold: a crash between authorize and reconcile
    // leaves it open with its exposure still counted.
    harness
        .budget_store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            requested_exposure_units: 70,
            max_cost_per_invocation: Some(70),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-orphan".to_string()),
            event_id: Some("hold-orphan:authorize".to_string()),
            authority: None,
            payment_journal: None,
        })?;
    assert_eq!(harness.budget_store.open_hold_count()?, 1);

    // A zero horizon makes the orphan immediately eligible; the sweeper
    // runs once at start before settling into its interval.
    harness.kernel.start_budget_hold_sweeper(3_600, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while harness.budget_store.open_hold_count()? != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "sweeper did not expire the orphaned hold in time"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Capacity returned by exactly the remainder; no spend recorded.
    let usage = harness
        .budget_store
        .get_usage("cap", 0)?
        .expect("usage record");
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.total_cost_realized_spend, 0);

    harness.cleanup();
    Ok(())
}
