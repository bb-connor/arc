use super::*;
use chio_core::capability::attenuation::{delegate, scope_hash};
use chio_core::capability::token::CapabilityTokenBody;
use chio_kernel::revocation_store::RevocationStoreError;
use chio_kernel::RevocationStore;
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;
use chio_store_sqlite::{SqliteAdmissionOperationStore, SqliteReceiptStore};

#[derive(Clone, Copy)]
pub(super) enum ClockFault {
    Unavailable,
    Regress,
}

pub(super) struct SharedClock {
    epoch_ms: u64,
    current_ms: AtomicU64,
    kernel_fault: AtomicU8,
    triggered: AtomicU8,
}

struct ClockPort {
    source: Arc<SharedClock>,
    kernel: bool,
}

impl Clock for ClockPort {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let fault = if self.kernel {
            self.source.kernel_fault.swap(0, Ordering::SeqCst)
        } else {
            0
        };
        if fault != 0 {
            self.source.triggered.store(fault, Ordering::SeqCst);
        }
        if fault == 1 {
            return Err(ClockError::Unavailable);
        }
        let now = self.source.now();
        let monotonic = now
            .checked_sub(self.source.epoch_ms)
            .and_then(|elapsed| elapsed.checked_mul(1_000_000))
            .ok_or(ClockError::Overflow)?;
        let emitted = if fault == 2 {
            now.checked_sub(1).ok_or(ClockError::BeforeEpoch)?
        } else {
            now
        };
        Ok(ClockReading::new(
            UnixMillis::new(emitted),
            MonotonicInstant::from_nanos(monotonic),
        ))
    }
}

impl SharedClock {
    pub(super) fn now(&self) -> u64 {
        self.current_ms.load(Ordering::SeqCst)
    }

    fn port(self: &Arc<Self>, kernel: bool) -> Arc<dyn Clock> {
        Arc::new(ClockPort {
            source: self.clone(),
            kernel,
        })
    }

    pub(super) fn fail_next_kernel_read(&self, fault: ClockFault) {
        self.triggered.store(0, Ordering::SeqCst);
        self.kernel_fault.store(
            match fault {
                ClockFault::Unavailable => 1,
                ClockFault::Regress => 2,
            },
            Ordering::SeqCst,
        );
    }

    pub(super) fn assert_triggered(&self, fault: ClockFault) {
        assert_eq!(
            self.triggered.load(Ordering::SeqCst),
            match fault {
                ClockFault::Unavailable => 1,
                ClockFault::Regress => 2,
            }
        );
    }

    fn elapse_recovery_lease(&self) -> TestResult {
        self.current_ms
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                now.checked_add(60_001)
            })
            .map_err(|_| "shared trusted clock overflow")?;
        Ok(())
    }
}

struct PreparedCaller {
    request: ToolCallRequest,
    authorization: SignedCallerDispatchAuthorizationV1,
    revocation_id: Option<String>,
    effects: Arc<AtomicU64>,
}

pub(super) struct RecordedCaller {
    pub(super) request: ToolCallRequest,
    pub(super) authorization: SignedCallerDispatchAuthorizationV1,
    pub(super) report: SignedCallerDeliveryReportV1,
    pub(super) revocation_id: Option<String>,
    pub(super) original_operation: AdmissionOperationV1,
    pub(super) original_blob: CanonicalInvocationBlobV1,
    pub(super) effects: Arc<AtomicU64>,
}

impl RecordedCaller {
    pub(super) fn id(&self) -> &AdmissionOperationId {
        &self.authorization.authorization.invocation.operation_id
    }
}

pub(super) struct PendingCallers {
    pub(super) kernel: ChioKernel,
    pub(super) operations: Arc<SqliteAdmissionOperationStore>,
    pub(super) authority: SqliteAuthorityStore,
    pub(super) fence: StoreMutationFence,
    pub(super) callers: [RecordedCaller; 2],
    pub(super) clock: Arc<SharedClock>,
    pub(super) remote_invocations: Arc<AtomicU64>,
    ledger: SqliteCallerExecutionLedger,
    executor: CallerExecutorIdentityV1,
    executor_key: Keypair,
    _directory: tempfile::TempDir,
}

#[derive(Debug, PartialEq)]
pub(super) struct Snapshot {
    pub(super) operation: AdmissionOperationV1,
    pub(super) raw_digest: String,
    pub(super) outcome: ToolOutcomeRecordV1,
    pub(super) evaluation: Option<PostReturnEvaluationRecordV1>,
    pub(super) status: Option<AdmissionRecoveryStatusV1>,
    pub(super) usage: Option<chio_kernel::budget_store::BudgetUsageRecord>,
    pub(super) effects: u64,
}

fn configure(
    authority: &SqliteAuthorityStore,
    clock: &Arc<SharedClock>,
    signer: &Keypair,
    receipt_path: &std::path::Path,
    executor: &CallerExecutorIdentityV1,
    remote_invocations: &Arc<AtomicU64>,
) -> TestResult<ChioKernel> {
    let mut kernel = ChioKernel::new_with_clock(kernel_config(signer.clone()), clock.port(true));
    kernel.set_receipt_store_handle(Arc::new(SqliteReceiptStore::open_with_clock(
        receipt_path,
        clock.port(false),
    )?))?;
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
    kernel.set_caller_executor(executor.clone())?;
    let nonce_config = chio_kernel::execution_nonce::ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 16,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(
            chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&nonce_config),
        ),
    );
    kernel.register_tool_server(Box::new(MutationServer {
        invocations: remote_invocations.clone(),
    }));
    Ok(kernel)
}

fn prepare_caller(
    kernel: &ChioKernel,
    signer: &Keypair,
    mode: RevocationMode,
    label: &str,
    now: u64,
) -> TestResult<PreparedCaller> {
    let subject = Keypair::generate();
    let (capability, revocation_id) = if matches!(mode, RevocationMode::Ancestor) {
        let parent_subject = Keypair::generate();
        let mut parent_scope = scope();
        let grant = parent_scope
            .grants
            .first_mut()
            .ok_or("original parent grant")?;
        grant.operations.push(Operation::Delegate);
        let parent =
            kernel.issue_capability(&parent_subject.public_key(), parent_scope.clone(), 300)?;
        let _ = kernel.set_capability_trust_root(signer.public_key(), scope_hash(&parent_scope)?);
        kernel.register_delegation_parent(&parent)?;
        let child_scope = scope();
        let link = delegate(
            &parent,
            &child_scope,
            &parent_subject,
            &subject.public_key(),
            chio_core_types::ScopeAttenuation::empty(),
            now / 1_000,
            [21; 16],
        )?;
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("caller-recovery-child-{label}"),
                issuer: signer.public_key(),
                subject: subject.public_key(),
                scope: child_scope,
                issued_at: now / 1_000,
                expires_at: parent.expires_at,
                delegation_chain: link.complete_chain(),
                aggregate_invocation_budget: None,
            },
            signer,
        )?;
        assert!(capability.verify_signature()?);
        assert_eq!(capability.delegation_chain.len(), 1);
        assert_eq!(
            capability
                .delegation_chain
                .first()
                .ok_or("signed ancestor")?
                .capability_id,
            parent.id
        );
        (capability, Some(parent.id))
    } else {
        let capability = kernel.issue_capability(&subject.public_key(), scope(), 300)?;
        let revoked = matches!(mode, RevocationMode::Leaf).then(|| capability.id.clone());
        (capability, revoked)
    };
    let mut original = request(&capability);
    original.request_id = format!("caller-recovery-{label}");
    let reserved = kernel.reserve_caller_execution_blocking(&original)?;
    assert_eq!(reserved.verdict, Verdict::Allow);
    assert!(reserved.receipt.verify_signature()?);
    let nonce = reserved
        .execution_nonce
        .ok_or("original kernel reservation nonce")?;
    let authorization = match kernel.start_caller_execution_blocking(&nonce, &original.arguments)? {
        CallerStartResponse::Authorized(authorization) => *authorization,
        CallerStartResponse::Denied(_) => {
            return Err("original supported caller start denied".into())
        }
    };
    authorization.verify_for_claim(
        &signer.public_key(),
        &authorization.authorization.executor,
        &authorization.authorization.invocation,
        now,
    )?;
    Ok(PreparedCaller {
        request: original,
        authorization,
        revocation_id,
        effects: Arc::new(AtomicU64::new(0)),
    })
}

fn record_caller(
    kernel: &mut ChioKernel,
    authority: &SqliteAuthorityStore,
    clock: &Arc<SharedClock>,
    executor_key: &Keypair,
    ledger: &SqliteCallerExecutionLedger,
    prepared: PreparedCaller,
    revoke: bool,
) -> TestResult<RecordedCaller> {
    let effects = prepared.effects.clone();
    let report = ledger.execute_once(
        &prepared.authorization,
        &kernel.public_key(),
        &prepared.authorization.authorization.invocation,
        executor_key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(CallerExecutionReport {
                output: serde_json::json!({"original_caller_effect": true}),
                realized_cost: None,
            })
        },
    )?;
    let reached = Arc::new(AtomicU64::new(0));
    let revocation_result = Arc::new(Mutex::new(None::<Result<bool, RevocationStoreError>>));
    let native_revocations = Arc::new(authority.revocation_store());
    let revoke_id = revoke.then(|| prepared.revocation_id.clone()).flatten();
    let observed_id = revoke_id.clone();
    let callback_count = reached.clone();
    let callback_result = revocation_result.clone();
    let callback_clock = clock.clone();
    kernel.install_durable_finalization_cutpoint(Arc::new(move |cutpoint| {
        if cutpoint == DurableFinalizationCutpoint::ToolReturnRecorded {
            callback_count.fetch_add(1, Ordering::SeqCst);
            if let Some(id) = revoke_id.as_ref() {
                let result = native_revocations.revoke(id);
                if let Ok(mut slot) = callback_result.lock() {
                    *slot = Some(result);
                }
            } else {
                callback_clock.fail_next_kernel_read(ClockFault::Unavailable);
            }
        }
    }));
    let error = kernel
        .reconcile_authenticated_caller_execution_blocking(&prepared.authorization, &report)
        .err()
        .ok_or("original report must stop after authenticated return capture")?;
    assert_eq!(reached.load(Ordering::SeqCst), 1);
    if let Some(id) = observed_id.as_ref() {
        assert!(revocation_result
            .lock()
            .map_err(|_| "revocation result lock")?
            .take()
            .ok_or("native revocation callback result")??);
        assert!(authority.revocation_store().is_revoked(id)?);
        require_revocation(
            &error,
            if prepared.request.capability.delegation_chain.is_empty() {
                RevocationMode::Leaf
            } else {
                RevocationMode::Ancestor
            },
            id,
        )?;
    } else {
        clock.assert_triggered(ClockFault::Unavailable);
        require_clock(&error, ClockError::Unavailable)?;
    }
    let operations = authority.admission_operation_store();
    let id = &prepared.authorization.authorization.invocation.operation_id;
    let original_operation = operations
        .load_by_operation_id(id)?
        .ok_or("captured caller operation")?;
    assert_eq!(
        original_operation.state(),
        AdmissionOperationState::Finalizing
    );
    let original_blob = authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(id)?
        .ok_or("authentic retained caller return")?
        .canonical_blob()?;
    Ok(RecordedCaller {
        request: prepared.request,
        authorization: prepared.authorization,
        report,
        revocation_id: observed_id,
        original_operation,
        original_blob,
        effects: prepared.effects,
    })
}

impl PendingCallers {
    pub(super) fn new(mode: RevocationMode) -> TestResult<Self> {
        let directory = chio_test_support::private_tempdir()?;
        let database = directory.path().join("authority.db");
        let locks = directory.path().join("locks");
        let receipts = directory.path().join("receipts.db");
        create_private_directory(&locks)?;
        SqliteAuthorityStore::provision(&database, &locks)?;
        let epoch_ms = now_unix_ms()? / 1_000 * 1_000;
        let clock = Arc::new(SharedClock {
            epoch_ms,
            current_ms: AtomicU64::new(epoch_ms),
            kernel_fault: AtomicU8::new(0),
            triggered: AtomicU8::new(0),
        });
        let signer = Keypair::generate();
        let executor_key = Keypair::generate();
        let executor = CallerExecutorIdentityV1 {
            executor_id: AdmissionIdentifier::try_new("executor_id", "caller-recovery-executor")?,
            public_key: executor_key.public_key(),
            key_epoch: 1,
        };
        let ledger = SqliteCallerExecutionLedger::provision_with_clock(
            &directory.path().join("executor.db"),
            executor.clone(),
            4,
            clock.port(false),
        )?;
        let remote_invocations = Arc::new(AtomicU64::new(0));
        let (callers, old_fence) = {
            let authority = SqliteAuthorityStore::open_serving_with_clock(
                &database,
                &locks,
                clock.port(false),
            )?;
            let mut kernel = configure(
                &authority,
                &clock,
                &signer,
                &receipts,
                &executor,
                &remote_invocations,
            )?;
            let first = prepare_caller(&kernel, &signer, mode, "a", clock.now())?;
            let second = prepare_caller(&kernel, &signer, mode, "b", clock.now())?;
            let (first, second) = if first.authorization.authorization.invocation.operation_id
                < second.authorization.authorization.invocation.operation_id
            {
                (first, second)
            } else {
                (second, first)
            };
            let first = record_caller(
                &mut kernel,
                &authority,
                &clock,
                &executor_key,
                &ledger,
                first,
                true,
            )?;
            let second = record_caller(
                &mut kernel,
                &authority,
                &clock,
                &executor_key,
                &ledger,
                second,
                false,
            )?;
            ([first, second], authority.mutation_fence())
        };
        clock.elapse_recovery_lease()?;
        let authority =
            SqliteAuthorityStore::open_serving_with_clock(&database, &locks, clock.port(false))?;
        let fence = authority.mutation_fence();
        assert!(fence.owner_epoch > old_fence.owner_epoch);
        let operations = Arc::new(authority.admission_operation_store());
        let kernel = configure(
            &authority,
            &clock,
            &signer,
            &receipts,
            &executor,
            &remote_invocations,
        )?;
        let pending = Self {
            kernel,
            operations,
            authority,
            fence,
            callers,
            clock,
            remote_invocations,
            ledger,
            executor,
            executor_key,
            _directory: directory,
        };
        pending.require_originals()?;
        Ok(pending)
    }

    pub(super) fn require_originals(&self) -> TestResult {
        let [first, second] = &self.callers;
        assert!(first.id() < second.id());
        let page = self.operations.recovery_page(AdmissionRecoveryPageQuery {
            not_after_unix_ms: self.clock.now(),
            candidate_limit: 2,
            after_operation_id: None,
            fence: &self.fence,
        })?;
        let [first_page, second_page] = page.operations.as_slice() else {
            return Err("exact two retained caller recovery candidates required".into());
        };
        assert_eq!(page.scanned_candidates, 2);
        assert_eq!(first_page.binding().operation_id(), first.id());
        assert_eq!(second_page.binding().operation_id(), second.id());
        for caller in &self.callers {
            let operation = self
                .operations
                .load_by_operation_id(caller.id())?
                .ok_or("original qualified caller")?;
            assert_eq!(operation, caller.original_operation);
            assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
            assert_eq!(
                operation.dispatch_commit(),
                Some(&caller.authorization.authorization.committed.dispatch_commit)
            );
            let (_, original) = self
                .operations
                .load_retained_tool_request(caller.id(), &self.fence, self.clock.now())?
                .ok_or("original fenced caller request")?;
            let raw = self
                .authority
                .tool_outcome_store()
                .load_raw_invocation_by_operation(caller.id())?
                .ok_or("original qualified caller report")?;
            let blob = raw.canonical_blob()?;
            if blob != caller.original_blob {
                return Err("sealed caller return changed".into());
            }
            let persisted = raw.to_persisted();
            let evidence = persisted
                .caller_delivery_evidence
                .ok_or("authenticated caller report evidence")?;
            assert_eq!(evidence.authorization, caller.authorization);
            assert_eq!(evidence.report, caller.report);
            evidence.report.verify(
                &caller.authorization,
                &self.kernel.public_key(),
                &self.executor,
                &caller.authorization.authorization.invocation,
            )?;
            let digest = sha256_hex(&caller.report.canonical_bytes()?);
            assert_eq!(
                persisted
                    .receipt_metadata_snapshot
                    .as_ref()
                    .and_then(|m| m.pointer("/caller_delivery/report_digest"))
                    .and_then(serde_json::Value::as_str),
                Some(digest.as_str())
            );
            assert_eq!(
                persisted
                    .request_canonical_json
                    .as_deref()
                    .ok_or("original public retained recovery request")?
                    .as_bytes(),
                canonical_json_bytes(original.request_for_revalidation())?.as_slice()
            );
            assert_eq!(
                operation.binding().request_binding_hash(),
                &caller
                    .authorization
                    .authorization
                    .invocation
                    .request_binding_hash
            );
            assert_eq!(
                canonical_json_bytes(&original.request_for_revalidation().capability)?,
                canonical_json_bytes(&caller.request.capability)?
            );
            assert_eq!(
                original.request_for_revalidation().arguments,
                caller.request.arguments
            );
            assert_eq!(
                self.authority
                    .tool_outcome_store()
                    .lookup_by_operation(caller.id())?
                    .ok_or("original returned outcome")?
                    .disposition(),
                &chio_kernel::tool_outcome::ResolvedToolOutcomeV1::Returned
            );
            assert_eq!(
                self.authority
                    .tool_outcome_store()
                    .lookup_post_return_evaluation(caller.id())?,
                None
            );
            assert_eq!(
                self.operations
                    .load_recovery_status(caller.id(), &self.fence, self.clock.now())?,
                None
            );
            assert_eq!(
                self.operations
                    .load_payment_journal(caller.id().as_str(), &self.fence)?,
                None
            );
            assert_eq!(caller.effects.load(Ordering::SeqCst), 1);
        }
        assert_eq!(self.remote_invocations.load(Ordering::SeqCst), 0);
        Ok(())
    }

    pub(super) fn snapshot(&self) -> TestResult<Vec<Snapshot>> {
        self.callers
            .iter()
            .map(|caller| {
                let outcomes = self.authority.tool_outcome_store();
                let raw = outcomes
                    .load_raw_invocation_by_operation(caller.id())?
                    .ok_or("snapshot retained caller output")?;
                Ok(Snapshot {
                    operation: self
                        .operations
                        .load_by_operation_id(caller.id())?
                        .ok_or("snapshot caller operation")?,
                    raw_digest: sha256_hex(raw.canonical_blob()?.bytes()),
                    outcome: outcomes
                        .lookup_by_operation(caller.id())?
                        .ok_or("snapshot caller outcome")?,
                    evaluation: outcomes.lookup_post_return_evaluation(caller.id())?,
                    status: self.operations.load_recovery_status(
                        caller.id(),
                        &self.fence,
                        self.clock.now(),
                    )?,
                    usage: self
                        .authority
                        .budget_store()
                        .get_usage(&caller.request.capability.id, 0)?,
                    effects: caller.effects.load(Ordering::SeqCst),
                })
            })
            .collect()
    }

    pub(super) fn finish_fresh_caller(&self) -> TestResult {
        let subject = Keypair::generate();
        let cap = self
            .kernel
            .issue_capability(&subject.public_key(), scope(), 300)?;
        let mut request = request(&cap);
        request.request_id = "unrelated-fresh-cap-after-retained-caller".into();
        let reserved = self.kernel.reserve_caller_execution_blocking(&request)?;
        assert_eq!(reserved.verdict, Verdict::Allow);
        let nonce = reserved
            .execution_nonce
            .ok_or("fresh original caller nonce")?;
        let authorization = match self
            .kernel
            .start_caller_execution_blocking(&nonce, &request.arguments)?
        {
            CallerStartResponse::Authorized(value) => *value,
            CallerStartResponse::Denied(_) => return Err("fresh unrelated caller denied".into()),
        };
        let count = AtomicU64::new(0);
        let report = self.ledger.execute_once(
            &authorization,
            &self.kernel.public_key(),
            &authorization.authorization.invocation,
            &self.executor_key,
            || {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"fresh_caller_effect": true}),
                    realized_cost: None,
                })
            },
        )?;
        let response = self
            .kernel
            .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(
            response.output,
            Some(chio_kernel::ToolCallOutput::Value(report.report.output))
        );
        assert!(response.receipt.verify_signature()?);
        assert_eq!(
            response.receipt.kernel_key,
            self.kernel.receipt_signing_public_key()
        );
        assert_eq!(response.receipt.capability_id, request.capability.id);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
