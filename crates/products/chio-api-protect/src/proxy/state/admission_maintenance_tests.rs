use super::*;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationState, AdmissionOperationStore, AdmissionRecoveryError,
    AdmissionRecoveryFailureKind, AdmissionRecoveryPageQuery,
};
use chio_kernel::payment::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, PaymentJournalState, PaymentRailMode, PaymentResult, RailSettlementStatus,
};
use chio_kernel::{
    KernelError, NestedFlowBridge, ToolCallRequest, ToolInvocationCost, ToolServerConnection,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "admission_maintenance_tests/lifecycle.rs"]
mod lifecycle;

struct ControlledClock {
    initial_ms: u64,
    elapsed_ms: AtomicU64,
    rejected: AtomicBool,
}

impl ControlledClock {
    fn advance_past(&self, deadline: u64) -> TestResult {
        let elapsed = deadline
            .checked_sub(self.initial_ms)
            .and_then(|elapsed| elapsed.checked_add(1))
            .ok_or("fixture deadline is outside its original clock epoch")?;
        self.elapsed_ms.store(elapsed, Ordering::SeqCst);
        Ok(())
    }
}

impl Clock for ControlledClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.rejected.load(Ordering::SeqCst) {
            return Err(ClockError::Unavailable);
        }
        let elapsed = self.elapsed_ms.load(Ordering::SeqCst);
        Ok(ClockReading::new(
            UnixMillis::new(self.initial_ms + elapsed),
            MonotonicInstant::from_nanos(elapsed * 1_000_000),
        ))
    }
}

#[derive(Default)]
struct RailTrace {
    pending: AtomicBool,
    dispatches: AtomicU64,
    authorizations: StdMutex<Vec<String>>,
    captures: StdMutex<Vec<(String, String, u64, String)>>,
    committed_intents: StdMutex<HashSet<(String, String, u64, String)>>,
    financial_effects: AtomicU64,
    gate: lifecycle::CaptureGate,
}

struct PendingRail(Arc<RailTrace>);

impl PaymentAdapter for PendingRail {
    fn rail_id(&self) -> &'static str {
        "api-protect-owned-retry-rail"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.0
            .authorizations
            .lock()
            .map_err(|_| PaymentError::RailError("fixture lock".into()))?
            .push(request.reference.clone());
        Ok(PaymentAuthorization {
            authorization_id: "original-host-authorization".into(),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.0
            .captures
            .lock()
            .map_err(|_| PaymentError::RailError("fixture lock".into()))?
            .push((
                authorization_id.into(),
                reference.into(),
                amount,
                currency.into(),
            ));
        let status = if self.0.pending.load(Ordering::SeqCst) {
            RailSettlementStatus::Pending
        } else {
            self.0.gate.wait()?;
            // The configured fixture rail commits at most one financial effect
            // for this original idempotent intent, even if recovery repeats it.
            if self
                .0
                .committed_intents
                .lock()
                .map_err(|_| PaymentError::RailError("fixture lock".into()))?
                .insert((
                    authorization_id.into(),
                    reference.into(),
                    amount,
                    currency.into(),
                ))
            {
                self.0.financial_effects.fetch_add(1, Ordering::SeqCst);
            }
            RailSettlementStatus::Captured
        };
        Ok(PaymentResult {
            transaction_id: authorization_id.into(),
            settlement_status: status,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Declined(
            "fixture must preserve its original capture intent".into(),
        ))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Declined(
            "fixture must preserve its original capture intent".into(),
        ))
    }
}

struct PaidOutput(Arc<RailTrace>);

#[async_trait::async_trait]
impl ToolServerConnection for PaidOutput {
    fn server_id(&self) -> &str {
        "api-protect-owned-retry-tool"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["pay".into()]
    }

    async fn invoke(
        &self,
        _tool: &str,
        _arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"paid_output": true}))
    }

    async fn invoke_with_cost(
        &self,
        tool: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        Ok((
            self.invoke(tool, arguments, bridge).await?,
            Some(ToolInvocationCost {
                units: 10,
                currency: "USD".into(),
                breakdown: None,
            }),
        ))
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    database: PathBuf,
    authority: Arc<chio_store_sqlite::SqliteAuthorityStore>,
    state: Arc<ProxyState>,
    source: Arc<ControlledClock>,
    trace: Arc<RailTrace>,
    request: ToolCallRequest,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        let database = directory.path().join("authority.db");
        let locks = directory.path().join("locks");
        fs::create_dir(&locks)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locks, fs::Permissions::from_mode(0o700))?;
        }
        let source = Arc::new(ControlledClock {
            initial_ms: chio_security_types::clock::SystemClock.unix_millis()?.get(),
            elapsed_ms: AtomicU64::new(0),
            rejected: AtomicBool::new(false),
        });
        let clock = clock::ProxyClock::new(source.clone());
        chio_store_sqlite::SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = Arc::new(
            chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
                &database,
                &locks,
                Arc::new(clock.clone()),
            )?,
        );
        let durable = DurableAdmissionStores {
            store: Arc::new(authority.admission_operation_store()),
            outcome_store: Arc::new(authority.tool_outcome_store()),
            fence: authority.mutation_fence(),
            budget_store: Arc::new(authority.budget_store()),
        };
        let budget = durable.budget_store.clone();
        let signer = Keypair::from_seed(&[27; 32]);
        let trace = Arc::new(RailTrace::default());
        trace.pending.store(true, Ordering::SeqCst);
        let kernel = build_mediation_kernel(
            &signer,
            budget.clone(),
            super::super::mediated::MediationPolicy {
                issuers: &[],
                hash: None,
                receipt_store: Some(Arc::new(authority.admission_operation_store())),
            },
            vec![Box::new(PaidOutput(trace.clone()))],
            Some(Box::new(PendingRail(trace.clone()))),
            Some(durable),
            Arc::new(clock.clone()),
        )?;
        let subject = Keypair::from_seed(&[28; 32]).public_key();
        let capability = kernel.issue_capability(
            &subject,
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "api-protect-owned-retry-tool".into(),
                    tool_name: "pay".into(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(10),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 10,
                        currency: "USD".into(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".into(),
                    }),
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            3600,
        )?;
        let request = serde_json::from_value(serde_json::json!({
            "request_id": "api-protect-owned-retry-request", "capability": capability,
            "tool_name": "pay", "server_id": "api-protect-owned-retry-tool",
            "agent_id": subject.to_hex(), "arguments": {},
        }))?;
        let approvals: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let contract = default_upstream_egress_contract("http://127.0.0.1:1")?;
        let state = Arc::new(ProxyState {
            clock,
            evaluator: RequestEvaluator::new_ephemeral_with_approval_store(
                Vec::new(),
                signer.clone(),
                "fixture-policy".into(),
                approvals.clone(),
            ),
            signer_keypair: signer.clone(),
            upstream: "http://127.0.0.1:1".into(),
            http_client: client_builder_with_contract(&contract).build()?,
            egress_contract: contract,
            approval_admin: ApprovalAdmin::new(approvals),
            approval_config: None,
            receipt_log: Mutex::new(ReceiptLog { receipts: vec![] }),
            tool_receipt_log: Mutex::new(ToolReceiptLog { receipts: vec![] }),
            receipt_store: None,
            revocation_store: None,
            revoked_capability_ids: Mutex::new(HashSet::new()),
            trusted_capability_issuers: vec![signer.public_key()],
            trusted_receipt_signers: vec![signer.public_key()],
            sidecar_control_token: None,
            budget_store: Some(budget),
            mediation_hold_capable: true,
            mediation_kernel: Some(Arc::new(Mutex::new(kernel))),
            minted_request_ids: Mutex::new(MintedRequestIdWindow::new(
                chio_kernel::DEFAULT_EXECUTION_NONCE_TTL_SECS,
            )),
            allow_advisory: false,
            receipt_backend: "fixture-joint",
            revocation_backend: "fixture-none",
        });
        Ok(Self {
            _directory: directory,
            database,
            authority,
            state,
            source,
            trace,
            request,
        })
    }

    fn finalizing_operation(&self) -> Result<AdmissionOperationId, Box<dyn std::error::Error>> {
        let connection = rusqlite::Connection::open_with_flags(
            &self.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let id: String = connection.query_row(
            "SELECT operation_id FROM admission_operations WHERE state='finalizing'",
            [],
            |row| row.get(0),
        )?;
        Ok(AdmissionOperationId::from_persisted(id)?)
    }

    fn expire_original_claim(&self, operation: &AdmissionOperationId) -> TestResult {
        let connection = rusqlite::Connection::open_with_flags(
            &self.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let expiry: i64 = connection.query_row(
            "SELECT recovery_expires_at_unix_ms FROM admission_operations WHERE operation_id=?1",
            [operation.as_str()],
            |row| row.get(0),
        )?;
        self.source.advance_past(u64::try_from(expiry)?)
    }
}

impl Fixture {
    async fn prepare_pending(
        &mut self,
    ) -> Result<
        (
            AdmissionOperationId,
            chio_kernel::admission_operation::AdmissionRecoveryStatusV1,
        ),
        Box<dyn std::error::Error>,
    > {
        let kernel = self
            .state
            .mediation_kernel
            .as_ref()
            .ok_or("original kernel")?
            .lock()
            .await;
        let preflight = kernel.evaluate_tool_call(&self.request).await?;
        assert_eq!(
            preflight.verdict,
            chio_kernel::Verdict::Allow,
            "{:?}",
            preflight.reason
        );
        self.request.execution_nonce = Some(*preflight.execution_nonce.ok_or("original nonce")?);
        let error = kernel
            .evaluate_tool_call(&self.request)
            .await
            .err()
            .ok_or("actual pending payment")?;
        assert!(
            matches!(&error, KernelError::AdmissionRecovery(failure) if matches!(failure.as_ref(),
            AdmissionRecoveryError::Item { kind: AdmissionRecoveryFailureKind::PaymentPending, .. })),
            "{error:?}"
        );
        let operation = self.finalizing_operation()?;
        self.expire_original_claim(&operation)?;
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
        drop(kernel);
        let status = self
            .authority
            .admission_operation_store()
            .load_recovery_status(
                &operation,
                &self.authority.mutation_fence(),
                self.state.clock.millis()?,
            )?
            .ok_or("actual pending deferral")?;
        assert!(status.quarantined);
        assert_eq!(self.trace.dispatches.load(Ordering::SeqCst), 1);
        Ok((operation, status))
    }
}

#[tokio::test]
async fn admission_host_retry_pending_payment_completes_without_new_request() -> TestResult {
    let mut fixture = Fixture::new()?;
    let operation_id;
    {
        let kernel = fixture
            .state
            .mediation_kernel
            .as_ref()
            .ok_or("original kernel")?
            .lock()
            .await;
        let preflight = kernel.evaluate_tool_call(&fixture.request).await?;
        assert_eq!(
            preflight.verdict,
            chio_kernel::Verdict::Allow,
            "{:?}",
            preflight.reason
        );
        assert_eq!(fixture.trace.dispatches.load(Ordering::SeqCst), 0);
        fixture.request.execution_nonce = Some(
            *preflight
                .execution_nonce
                .ok_or("original signed execution nonce")?,
        );
        let pending = kernel.evaluate_tool_call(&fixture.request).await;
        let error = pending
            .err()
            .ok_or("original pending payment must remain unsettled")?;
        assert!(
            matches!(&error,
            KernelError::AdmissionRecovery(failure) if matches!(failure.as_ref(),
                AdmissionRecoveryError::Item { kind: AdmissionRecoveryFailureKind::PaymentPending, .. }
            )),
            "{error:?}"
        );
        operation_id = fixture.finalizing_operation()?;
        assert_eq!(fixture.trace.dispatches.load(Ordering::SeqCst), 1);
        // The original same-fence coordinator still owns its persisted claim.
        // Recovery may inspect it only after this real claim expires.
        fixture.expire_original_claim(&operation_id)?;
        let candidate_page = fixture
            .authority
            .admission_operation_store()
            .recovery_page(AdmissionRecoveryPageQuery {
                not_after_unix_ms: fixture.state.clock.millis()?,
                candidate_limit: 16,
                after_operation_id: None,
                fence: &fixture.authority.mutation_fence(),
            })?;
        assert!(
            candidate_page
                .operations
                .iter()
                .any(|operation| operation.binding().operation_id() == &operation_id),
            "the actual expired original claim must be eligible before setup recovery"
        );
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    }
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let now = fixture.state.clock.millis()?;
    let marker = store
        .load_recovery_status(&operation_id, &fence, now)?
        .ok_or("pending deferral")?;
    assert!(marker.quarantined);
    let operation = store
        .load_by_operation_id(&operation_id)?
        .ok_or("original operation")?;
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    let journal = store
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or("original payment intent")?;
    assert_eq!(journal.state, PaymentJournalState::Settling);
    assert_eq!(journal.settle_amount_units, Some(10));
    let captures_before = fixture
        .trace
        .captures
        .lock()
        .map_err(|_| "trace lock")?
        .len();
    assert!(captures_before >= 1);
    fixture
        .source
        .advance_past(marker.deferral.retry_not_before_unix_ms)?;
    fixture.trace.pending.store(false, Ordering::SeqCst);
    let controller = Arc::new(ShutdownController::manual());
    let mut owner = AdmissionMaintenance::spawn(
        fixture
            .state
            .mediation_kernel
            .as_ref()
            .ok_or("original kernel")?
            .clone(),
        true,
        controller,
        Duration::from_millis(10),
    )?;
    let control = owner.control();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while control.health().recovered == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    owner.stop_and_join(Duration::from_secs(1)).await;
    assert!(control.health().worker_joined);
    let now = fixture.state.clock.millis()?;
    let marker = store
        .load_recovery_status(&operation_id, &fence, now)?
        .ok_or("retained recovery history")?;
    assert!(
        !marker.quarantined,
        "the owned host tick must retry due money without a new tool request"
    );
    assert!(marker.deferral.attempt_count >= 1);
    assert_eq!(
        store
            .load_by_operation_id(&operation_id)?
            .ok_or("recovered operation")?
            .state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(fixture.trace.dispatches.load(Ordering::SeqCst), 1);
    let authorizations = fixture
        .trace
        .authorizations
        .lock()
        .map_err(|_| "trace lock")?;
    assert_eq!(authorizations.as_slice(), [operation_id.as_str()]);
    let captures = fixture.trace.captures.lock().map_err(|_| "trace lock")?;
    assert!(captures.len() > captures_before);
    assert!(captures.iter().all(|entry| entry
        == &(
            "original-host-authorization".into(),
            operation_id.as_str().into(),
            10,
            "USD".into()
        )));
    assert_eq!(fixture.trace.financial_effects.load(Ordering::SeqCst), 1);
    Ok(())
}
