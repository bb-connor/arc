//! Kernel-surface tests for the durable payment journal: the money path
//! walks HoldPlaced -> Authorized -> Settling -> Settled -> Closed around
//! the rail calls, and boot reconciliation resolves every incomplete row to
//! exactly one terminal outcome.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

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
    /// like the in-tree prepaid rails.
    pub struct CountingRail {
        pub captures: AtomicUsize,
        pub releases: AtomicUsize,
    }

    impl CountingRail {
        pub fn new() -> Self {
            Self {
                captures: AtomicUsize::new(0),
                releases: AtomicUsize::new(0),
            }
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
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            Ok(chio_kernel::PaymentResult {
                transaction_id: authorization_id
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("auth-{reference}")),
                settlement_status: chio_kernel::RailSettlementStatus::Settled,
                metadata: serde_json::json!({}),
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
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
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
