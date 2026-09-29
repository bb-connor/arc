use super::*;
use chio_core::capability::scope::{Operation, ToolGrant};
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationState, AdmissionOperationStore,
    NativeSecurityAuthorityBindingV1,
};
use chio_kernel::budget_store::BudgetQuotaKey;
use chio_kernel::{
    BudgetStore, ChioKernel, KernelConfig, KernelError, NativeSecurityAdmissionContext,
    NativeSecurityFlowJoinAuthority, NestedFlowBridge, SecurityDispatchOutcomeHandle,
    SecurityInvocationContext, SecurityPreDispatchContext, SecurityPreDispatchHook,
    SecurityPreDispatchPolicy, ToolServerConnection, Verdict,
};
use chio_security_types::ports::IsolationEpochId;
use chio_store_sqlite::security_state::SqliteSecurityParticipantSource;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};

mod capture;

mod lifecycle;

#[path = "../../native_flow_nonce_tests.rs"]
mod nonce;

mod caller;

mod declassification;

#[cfg(unix)]
mod process_recovery;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn open_kernel(
    directory: &std::path::Path,
    authority: &SqliteAuthorityStore,
    signer: &Keypair,
    clock: Arc<FlowTestClock>,
) -> TestResult<(ChioKernel, Arc<AtomicUsize>)> {
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            ca_public_keys: vec![signer.public_key()],
            keypair: signer.clone(),
            max_delegation_depth: 5,
            policy_hash: chio_core::sha256_hex(b"native-flow-policy-test"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            allow_ephemeral_revocation_store: false,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        },
        clock,
    );
    let receipts = SqliteReceiptStore::open(directory.join("receipts.db"))?;
    receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
    kernel.set_receipt_store_handle(Arc::new(receipts))?;
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingServer(invocations.clone())));
    Ok((kernel, invocations))
}

// Test authority time is independent of scheduling, SQLite fsync and host load.
// Process recovery reconstructs this epoch from its witness, never from wall time.
const FIXTURE_EPOCH_MS: u64 = 1_800_000_000_000;

pub(super) fn now_ms() -> PortResult<u64> {
    Ok(FIXTURE_EPOCH_MS)
}

pub(super) struct FlowTestClock {
    pub mode: AtomicUsize,
    unix_ms: std::sync::atomic::AtomicU64,
}

impl Default for FlowTestClock {
    fn default() -> Self {
        Self::at(FIXTURE_EPOCH_MS)
    }
}

impl FlowTestClock {
    fn at(unix_ms: u64) -> Self {
        Self {
            mode: AtomicUsize::new(0),
            unix_ms: std::sync::atomic::AtomicU64::new(unix_ms),
        }
    }

    fn snapshot(&self) -> u64 {
        self.unix_ms.load(Ordering::SeqCst)
    }

    fn advance_to(&self, unix_ms: u64) -> TestResult {
        self.unix_ms
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |previous| {
                (unix_ms >= previous).then_some(unix_ms)
            })
            .map_err(|_| "fixture clock cannot regress")?;
        Ok(())
    }
}

impl chio_security_types::clock::Clock for FlowTestClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::{ClockError, ClockReading, MonotonicInstant, UnixMillis};
        let current_ms = self.snapshot();
        let unix_ms = match self.mode.load(Ordering::SeqCst) {
            0 => current_ms,
            1 => 0,
            2 => (1_u64 << 53) - 1,
            3 => panic!("native policy clock panic"),
            _ => return Err(ClockError::Unavailable),
        };
        // Wall-time fault modes must reach the wall-time rejection boundary,
        // without an unrelated overflow in the fixture's monotonic domain.
        let elapsed_ms = current_ms.saturating_sub(FIXTURE_EPOCH_MS);
        let nanos = elapsed_ms
            .checked_mul(1_000_000)
            .ok_or(ClockError::Overflow)?;
        Ok(ClockReading::new(
            UnixMillis::new(unix_ms),
            MonotonicInstant::from_nanos(nanos),
        ))
    }
}

/// Real admission authority and source import. No legacy flow backend is given
/// to the resolver. The test-only hook joins supplied labels before budget.
pub(super) struct Fixture {
    kernel: ChioKernel,
    pub(super) clock: Arc<FlowTestClock>,
    authority: SqliteAuthorityStore,
    pub binding: NativeSecurityAuthorityBindingV1,
    pub request: ToolCallRequest,
    context: SecurityInvocationContext,
    invocations: Arc<AtomicUsize>,
    hook: Arc<JoinHook>,
    agent: Keypair,
    signer: Keypair,
    // Fields drop in declaration order. Close live stores before deleting files.
    _directory: tempfile::TempDir,
}

impl Fixture {
    pub fn new(labels: [InformationLabel; 3]) -> TestResult<Self> {
        Self::new_with_seed(labels, |_| Ok(None))
    }

    pub fn new_with_seed(
        labels: [InformationLabel; 3],
        seed: impl FnOnce(&FlowStateKey) -> TestResult<Option<FlowJoinRequest>>,
    ) -> TestResult<Self> {
        Self::new_with_seed_and_dpop(labels, seed, false)
    }

    fn new_with_seed_and_dpop(
        labels: [InformationLabel; 3],
        seed: impl FnOnce(&FlowStateKey) -> TestResult<Option<FlowJoinRequest>>,
        extra_dpop_grant: bool,
    ) -> TestResult<Self> {
        Self::new_with_credential_profile(labels, seed, extra_dpop_grant, false)
    }

    fn new_with_credential_profile(
        labels: [InformationLabel; 3],
        seed: impl FnOnce(&FlowStateKey) -> TestResult<Option<FlowJoinRequest>>,
        extra_dpop_grant: bool,
        governed: bool,
    ) -> TestResult<Self> {
        Self::new_selected_profile(labels, seed, extra_dpop_grant, governed, false)
    }

    fn new_with_declassification_profile() -> TestResult<Self> {
        Self::new_selected_profile(
            std::array::from_fn(|_| InformationLabel::bottom()),
            |_| Ok(None),
            false,
            false,
            true,
        )
    }

    fn new_selected_profile(
        labels: [InformationLabel; 3],
        seed: impl FnOnce(&FlowStateKey) -> TestResult<Option<FlowJoinRequest>>,
        extra_dpop_grant: bool,
        governed: bool,
        declassification: bool,
    ) -> TestResult<Self> {
        #[cfg(unix)]
        let directory = process_recovery::fixture_directory()?;
        #[cfg(not(unix))]
        let directory = tempdir()?;
        let locks = directory.path().join("locks");
        std::fs::create_dir(&locks)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [directory.path(), locks.as_path()] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let database = directory.path().join("admission.db");
        SqliteAuthorityStore::provision(&database, &locks)?;
        let clock = Arc::new(FlowTestClock::default());
        let authority =
            SqliteAuthorityStore::open_serving_with_clock(database, locks, clock.clone())?;
        let signer = Keypair::generate();
        let (mut kernel, invocations) =
            open_kernel(directory.path(), &authority, &signer, clock.clone())?;
        kernel.reconcile_durable_admission_startup()?;

        let agent = Keypair::generate();
        let mut request = flow_request();
        let mut grants = vec![ToolGrant {
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            operations: vec![Operation::Invoke],
            constraints: if governed {
                vec![chio_core::capability::scope::Constraint::GovernedIntentRequired]
            } else {
                Vec::new()
            },
            max_invocations: Some(if declassification { 2 } else { 1 }),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }];
        if extra_dpop_grant {
            let mut required = grants[0].clone();
            required.dpop_required = Some(true);
            grants.push(required);
        }
        request.capability = kernel.issue_capability(
            &agent.public_key(),
            ChioScope {
                grants,
                ..ChioScope::default()
            },
            600,
        )?;
        request.agent_id = agent.public_key().to_hex();
        let mut context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            TenantId::new("native-tenant")?,
            SessionId::new("native-session")?,
            PrincipalId::new(request.agent_id.clone())?,
            IsolationEpochId::new("native-epoch")?,
            LineageId::new(request.capability.id.clone())?,
            1,
        ));

        let source_path = directory.path().join("source.db");
        let source_store =
            SqliteSecurityStateStore::open_with_trusted_clock(&source_path, clock.clone())?;
        if declassification {
            // Explicitly select this lifecycle before retirement and native
            // initialization. Native dispatch never rewrites imported status.
            source_store.seal_declassification_live_dispatch()?;
        }
        if let Some(seed) = seed(&super::super::super::flow_key(context.as_v1()))? {
            let snapshot = source_store.join(&seed)?;
            if seed.key == super::super::super::flow_key(context.as_v1()) {
                context = SecurityInvocationContext::v1(
                    context
                        .as_v1()
                        .clone()
                        .with_flow_state_generation(snapshot.context_generation),
                );
            }
        }
        drop(source_store);
        let source = SqliteSecurityParticipantSource::open(source_path)?;
        let store = authority.admission_operation_store();
        let fence = authority.mutation_fence();
        let selected = AdmissionIdentifier::try_new("authority", "native-flow-test")?;
        let now = now_ms()?;
        let expected =
            store.expect_security_participant_source(&selected, &selected, &source, &fence, now)?;
        store.import_security_participant_source(
            &selected,
            expected.expectation_id(),
            &source,
            &fence,
            now,
        )?;
        let binding = store
            .hydrate_security_participant_state(&selected, expected.expectation_id(), &fence, now)?
            .admission_binding()?;

        let hook = Arc::new(JoinHook {
            binding: binding.clone(),
            labels,
            joins: AtomicUsize::new(0),
            legacy_dispatch: AtomicUsize::new(0),
        });
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(hook.clone());
        Ok(Self {
            kernel,
            clock,
            authority,
            binding,
            request,
            context,
            invocations,
            hook,
            agent,
            signer,
            _directory: directory,
        })
    }

    pub fn run(
        &mut self,
        resolver: Arc<NativeFlowResolver>,
        before_commit: impl Fn() + Send + Sync + 'static,
    ) -> TestResult<Result<NativeFlowCustody, NativeFlowError>> {
        self.run_policy(resolver, before_commit, false, None, None)
    }

    pub fn run_native(
        &mut self,
        resolver: Arc<NativeFlowResolver>,
    ) -> TestResult<Result<NativeFlowCustody, NativeFlowError>> {
        self.kernel.set_security_pre_dispatch_hook(resolver.clone());
        self.run_policy(resolver, || {}, true, None, None)
    }

    pub fn run_with_dispatch_ledger(
        &mut self,
        resolver: Arc<NativeFlowResolver>,
        grant_index: usize,
    ) -> TestResult<Result<NativeFlowCustody, NativeFlowError>> {
        self.run_policy(resolver, || {}, false, Some(grant_index), None)
    }

    pub fn run_ledger_write_fault(
        &mut self,
        resolver: Arc<NativeFlowResolver>,
        fault: super::ledger::WriteFault,
    ) -> TestResult<Result<NativeFlowCustody, NativeFlowError>> {
        self.run_policy(resolver, || {}, false, Some(0), Some(fault))
    }

    /// Close every owner handle before reopening under a new fence. Error is
    /// not absence: both committed egress phases must survive compensation.
    pub fn reopen_failed_dispatch_ledger(self) -> TestResult {
        let store = self.authority.admission_operation_store();
        let fence = self.authority.mutation_fence();
        let (operation, _) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &self.request.request_id)?,
                &fence,
                now_ms()?,
            )?
            .ok_or("failed operation")?;
        assert!(operation.state().is_terminal());
        let id = operation.binding().operation_id();
        let expected_egress = store
            .load_native_security_egress(id, &fence, now_ms()?)?
            .ok_or("failed operation egress")?
            .1
            .ok_or("committed egress")?;
        assert!(expected_egress.commitment.is_some());
        let expected_join = store
            .load_native_security_flow_join(id, &fence, now_ms()?)?
            .ok_or("failed operation join")?
            .1
            .ok_or("original join")?;
        assert!(store
            .load_native_dispatch_ledger(id, &fence, now_ms()?)?
            .is_none());
        drop(store);
        let Self {
            kernel,
            authority,
            _directory,
            clock,
            ..
        } = self;
        drop(kernel);
        drop(authority);
        let reopened = SqliteAuthorityStore::open_serving_with_clock(
            _directory.path().join("admission.db"),
            _directory.path().join("locks"),
            clock.clone(),
        )?;
        let current_fence = reopened.mutation_fence();
        assert!(current_fence.owner_epoch > fence.owner_epoch);
        let store = reopened.admission_operation_store();
        assert!(store
            .load_native_dispatch_ledger(id, &fence, now_ms()?)
            .is_err());
        assert!(store
            .load_native_dispatch_ledger(id, &current_fence, now_ms()?)?
            .is_none());
        let (current, egress) = store
            .load_native_security_egress(id, &current_fence, now_ms()?)?
            .ok_or("reopened egress operation")?;
        assert_eq!(current, operation);
        assert_eq!(egress.as_ref(), Some(&expected_egress));
        assert_eq!(
            store
                .load_native_security_flow_join(id, &current_fence, now_ms()?)?
                .ok_or("reopened original join")?
                .1
                .as_ref(),
            Some(&expected_join)
        );
        let usage = reopened
            .budget_store()
            .get_invocation_quota_usage(&BudgetQuotaKey::grant(
                operation.binding().capability_id().as_str(),
                0,
            ))?
            .ok_or("compensated invocation quota")?;
        assert_eq!(
            (usage.reserved_invocations, usage.captured_invocations),
            (0, 0)
        );
        Ok(())
    }

    pub fn reopen_dispatch_ledger(
        self,
        operation: &chio_kernel::admission_operation::AdmissionOperationId,
        mutate: impl FnOnce(&rusqlite::Connection) -> TestResult,
    ) -> TestResult<chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1> {
        let Self {
            kernel,
            authority,
            _directory,
            clock,
            ..
        } = self;
        drop(kernel);
        drop(authority);
        let database = _directory.path().join("admission.db");
        let locks = _directory.path().join("locks");
        {
            let connection = rusqlite::Connection::open(&database)?;
            mutate(&connection)?;
        }
        let reopened =
            SqliteAuthorityStore::open_serving_with_clock(&database, &locks, clock.clone())?;
        reopened
            .admission_operation_store()
            .load_native_dispatch_ledger(operation, &reopened.mutation_fence(), clock.snapshot())?
            .ok_or_else(|| "reopened native dispatch ledger is absent".into())
    }

    pub fn budget_observer(&self) -> Arc<dyn Fn() -> PortResult<u64> + Send + Sync> {
        let budget = self.authority.budget_store();
        let key = BudgetQuotaKey::grant(self.request.capability.id.as_str(), 0);
        Arc::new(move || {
            budget
                .get_invocation_quota_usage(&key)
                .map(|usage| usage.map_or(0, |usage| u64::from(usage.reserved_invocations)))
                .map_err(|_| PortError::unavailable())
        })
    }

    pub fn deny_native(&mut self, resolver: Arc<NativeFlowResolver>, reason: &str) -> TestResult {
        self.kernel.set_security_pre_dispatch_hook(resolver);
        let response = self
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&self.request, &self.context)?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|actual| actual.contains(reason)),
            "{response:?}"
        );
        assert!(response.output.is_none());
        assert_eq!(self.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(self.hook.joins.load(Ordering::SeqCst), 0);
        assert_eq!(self.hook.legacy_dispatch.load(Ordering::SeqCst), 0);
        assert_eq!((self.budget_observer())()?, 0);
        let store = self.authority.admission_operation_store();
        let fence = self.authority.mutation_fence();
        let (operation, _) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &self.request.request_id)?,
                &fence,
                now_ms()?,
            )?
            .ok_or("original denied operation")?;
        assert!(operation.dispatch_commit().is_none());
        let (_, history) = store
            .load_native_security_input_join(operation.binding().operation_id(), &fence, now_ms()?)?
            .ok_or("denied operation")?;
        assert!(history.is_none());
        Ok(())
    }

    fn run_policy(
        &mut self,
        resolver: Arc<NativeFlowResolver>,
        before_commit: impl Fn() + Send + Sync + 'static,
        native: bool,
        ledger_grant: Option<usize>,
        ledger_fault: Option<super::ledger::WriteFault>,
    ) -> TestResult<Result<NativeFlowCustody, NativeFlowError>> {
        let result = Arc::new(Mutex::new(None));
        let calls = Arc::new(AtomicUsize::new(0));
        let failure_probe = ledger_fault.map(|fault| {
            Arc::new(super::ledger::LedgerFailureProbe::new(
                &self.authority,
                self._directory.path().join("admission.db"),
                fault,
            ))
        });
        self.kernel.install_native_egress_checkpoint_hook(Arc::new({
            let result = result.clone();
            let calls = calls.clone();
            let failure_probe = failure_probe.clone();
            let capture_probe = super::ledger::CaptureRefusalProbe::new(
                &self.authority,
                self._directory.path().join("admission.db"),
            );
            move |kernel, operation, request, context| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
                let run = || {
                    let custody = kernel.prepare_native_security_egress(
                        operation.binding().operation_id(),
                        request,
                        context,
                    )?;
                    assert!(std::ptr::eq(custody.request(), request));
                    assert_eq!(custody.operation_id(), operation.binding().operation_id());
                    assert_eq!(custody.operation_version(), operation.version());
                    assert_eq!(
                        custody.kernel_policy_hash(),
                        chio_core::sha256_hex(b"native-flow-policy-test")
                    );
                    assert!(
                        custody.validate_current()? >= custody.observation().observed_at_unix_ms()
                    );
                    let prepared = resolver.prepare_dispatch(custody)?;
                    let evidence = prepared.policy_evidence().canonical_bytes().to_vec();
                    let evidence_digest = prepared.policy_evidence().digest();
                    before_commit();
                    if let Some(probe) = &failure_probe {
                        probe
                            .install()
                            .map_err(|error| KernelError::Internal(error.to_string()))?;
                    }
                    let custody = match ledger_grant {
                        Some(grant) => prepared.commit_custody_with_dispatch_ledger(grant)?,
                        None => prepared.commit_custody()?,
                    };
                    assert_eq!(custody.policy_evidence().canonical_bytes(), evidence);
                    assert_eq!(custody.policy_evidence().digest(), evidence_digest);
                    Ok(custody)
                };
                let outcome = run();
                if let Some(probe) = &failure_probe {
                    if let Err(error) = probe.verify(kernel, operation, &outcome) {
                        panic!("partial native ledger write violated custody: {error}");
                    }
                }
                if let Ok(custody) = &outcome {
                    if custody.dispatch_ledger().is_some() {
                        if let Err(error) = capture_probe.verify_invalid_ledger_grant(
                            kernel, operation, request, context, custody,
                        ) {
                            panic!("physical ledger grant validation changed custody: {error}");
                        }
                        if let Err(error) =
                            capture_probe.verify(kernel, operation, custody.dispatch_ledger())
                        {
                            panic!("retained ledger bypassed native capture refusal: {error}");
                        }
                    }
                }
                if let Ok(mut slot) = result.lock() {
                    *slot = Some(outcome);
                }
            }
        }));
        let response = self
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&self.request, &self.context)?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(
            response.reason.as_deref(),
            Some("native security dispatch lifecycle is unsupported")
        );
        assert!(response.output.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(self.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(self.hook.joins.load(Ordering::SeqCst), usize::from(!native));
        assert_eq!(self.hook.legacy_dispatch.load(Ordering::SeqCst), 0);
        let usage =
            self.authority
                .budget_store()
                .get_invocation_quota_usage(&BudgetQuotaKey::grant(
                    self.request.capability.id.as_str(),
                    0,
                ))?;
        assert_eq!(
            usage
                .map(|u| (u.reserved_invocations, u.captured_invocations))
                .unwrap_or((0, 0)),
            (0, 0)
        );
        let outcome = result
            .lock()
            .map_err(|_| "native checkpoint poisoned")?
            .take()
            .ok_or("native checkpoint did not run")?;
        let store = self.authority.admission_operation_store();
        let fence = self.authority.mutation_fence();
        let (operation, original) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &self.request.request_id)?,
                &fence,
                now_ms()?,
            )?
            .ok_or("retained operation")?;
        assert!(operation.dispatch_commit().is_none());
        let (_, join) = store
            .load_native_security_flow_join(operation.binding().operation_id(), &fence, now_ms()?)?
            .ok_or("native operation")?;
        let join = join.ok_or("original input join")?;
        if native {
            let (_, input) = store
                .load_native_security_input_join(
                    operation.binding().operation_id(),
                    &fence,
                    now_ms()?,
                )?
                .ok_or("input operation")?;
            let input = input.ok_or("input history")?;
            input.validate()?;
            assert_eq!(input.join, join);
        } else {
            assert_eq!(
                join.command.transition_id,
                RecordId::new("native-policy-input")?
            );
            assert_eq!(join.command.principal_join, self.hook.labels[0]);
        }
        let (_, history) = store
            .load_native_security_egress(operation.binding().operation_id(), &fence, now_ms()?)?
            .ok_or("native operation")?;
        if let Some(probe) = &failure_probe {
            assert!(outcome.is_err());
            assert_eq!(history, Some(probe.history()?));
        } else {
            // Existing pre-acquisition failure cases must still leave no
            // egress history. Only explicit post-commit faults expect custody.
            assert_eq!(
                history.as_ref(),
                outcome
                    .as_ref()
                    .ok()
                    .and_then(NativeFlowCustody::egress_history)
            );
        }
        if let Ok(custody) = &outcome {
            assert_eq!(
                store
                    .load_native_dispatch_ledger(
                        operation.binding().operation_id(),
                        &fence,
                        now_ms()?
                    )?
                    .as_ref(),
                custody.dispatch_ledger()
            );
            assert_eq!(custody.operation_id(), operation.binding().operation_id());
            let policy: serde_json::Value =
                serde_json::from_slice(custody.policy_evidence().canonical_bytes())?;
            assert_eq!(
                policy["inputs"]["retained_request_digest"],
                chio_core::sha256_hex(original.canonical_bytes())
            );
            assert_eq!(
                custody.live_request_digest(),
                super::super::super::flow_dispatch::live_request_digest(&self.request)?
            );
            assert!(
                self.kernel
                    .prepare_native_security_egress(
                        custody.operation_id(),
                        &self.request,
                        &self.context,
                    )
                    .is_err(),
                "historical custody must not reopen terminal admission"
            );
        }
        Ok(outcome)
    }
}

struct JoinHook {
    binding: NativeSecurityAuthorityBindingV1,
    labels: [InformationLabel; 3],
    joins: AtomicUsize,
    legacy_dispatch: AtomicUsize,
}

impl SecurityPreDispatchHook for JoinHook {
    fn name(&self) -> &str {
        "native-policy-test-join"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.clone()))
    }
    fn prepare_native_admission(
        &self,
        _: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.joins.fetch_add(1, Ordering::SeqCst);
        authority.join(
            RecordId::new("native-policy-input")
                .map_err(|e| KernelError::Internal(e.to_string()))?,
            self.labels[0].clone(),
            self.labels[1].clone(),
            self.labels[2].clone(),
        )?;
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        self.legacy_dispatch.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::GuardDenied(
            "legacy dispatch is forbidden".into(),
        ))
    }
}

struct CountingServer(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "server-a"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["send".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

#[test]
fn native_fixture_clock_uses_a_stable_authority_epoch() -> TestResult {
    use chio_security_types::clock::Clock;
    assert_eq!(now_ms()?, 1_800_000_000_000);
    assert_eq!(FlowTestClock::default().unix_millis()?.get(), now_ms()?);
    let fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
    assert_eq!(fixture.request.capability.issued_at, now_ms()? / 1000);
    Ok(())
}
