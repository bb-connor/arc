// Native caller crash boundaries use real stores, process death and an external
// effect marker. The parent never reconstructs a live admission or permission.
use super::*;
use chio_kernel::caller_delivery::{CallerExecutorIdentityV1, SignedCallerDispatchAuthorizationV1};
use chio_kernel::{CallerExecutionReport, CallerStartCredentials, CallerStartResponse};
use chio_store_sqlite::caller_execution_ledger::{
    CallerExecutionLedgerError, SqliteCallerExecutionLedger,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {
    BeforeCaptureCommit,
    AfterCaptureCommit,
    Claimed,
    Effect,
    Report,
    OutputJoined,
    OutputJoinedChangedClassification,
    Finalization(FinalizationName),
}

impl Cut {
    fn effected(self) -> bool {
        !matches!(
            self,
            Self::BeforeCaptureCommit | Self::AfterCaptureCommit | Self::Claimed
        )
    }

    fn reported(self) -> bool {
        matches!(
            self,
            Self::Report
                | Self::OutputJoined
                | Self::OutputJoinedChangedClassification
                | Self::Finalization(_)
        )
    }
}

fn abort_at(cut: Cut) -> ! {
    eprintln!("native caller process cutpoint: {cut:?}");
    std::process::abort()
}

fn execute_child(cut: Cut, combined_disclosure: bool) -> TestResult {
    let (mut fixture, disclosure) = if combined_disclosure {
        let (fixture, key) = declassification::profile(true, 300)?;
        (fixture, Some(key))
    } else {
        (super::super::super::public_fixture()?, None)
    };
    fixture
        .kernel
        .set_security_pre_dispatch_hook(Arc::new(resolver(
            fixture.binding.clone(),
            disclosure.as_ref(),
        )?));
    nonce::execution::install_nonce(&mut fixture, 120);
    let key = Keypair::generate();
    let executor = CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor", "native-process-executor")?,
        public_key: key.public_key(),
        key_epoch: 71,
    };
    fixture.kernel.set_caller_executor(executor.clone())?;
    nonce::execution::issue(&mut fixture)?;
    let reserved = fixture
        .kernel
        .reserve_caller_execution_blocking_with_security_context(
            &fixture.request,
            &fixture.context,
        )?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let nonce = reserved.execution_nonce.ok_or("reserved nonce")?;
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture._directory.path().join("executor.db"),
        executor,
        2,
    )?;
    let root = PathBuf::from(std::env::var_os(ROOT).ok_or("process root")?);
    sync_write(
        &root.join("witness.json"),
        &chio_core::canonical_json_bytes(&caller_restart_witness(&fixture, disclosure.as_ref()))?,
        false,
    )?;
    sync_write(&root.join("executor-key"), key.seed_hex().as_bytes(), false)?;
    if matches!(cut, Cut::BeforeCaptureCommit | Cut::AfterCaptureCommit) {
        fixture
            .authority
            .admission_operation_store()
            .install_native_capture_transaction_cutpoint_for_test(
                if cut == Cut::BeforeCaptureCommit {
                    TransactionPoint::BeforeCommit
                } else {
                    TransactionPoint::CommittedBeforeAnchor
                },
            )?;
    }
    let credentials = CallerStartCredentials {
        dpop_proof: fixture.request.dpop_proof.clone(),
        approval_token: fixture.request.approval_token.clone(),
        approval_tokens: fixture.request.approval_tokens.clone(),
        threshold_approval_proposal: fixture.request.threshold_approval_proposal.clone(),
        declassification_grant: fixture.request.declassification_grant.clone(),
    };
    let authorization = match fixture
        .kernel
        .start_caller_execution_blocking_with_security_context(
            &nonce,
            &fixture.request.arguments,
            credentials,
            &fixture.context,
        )? {
        CallerStartResponse::Authorized(value) => *value,
        CallerStartResponse::Denied(value) => {
            return Err(format!("start denied: {:?}", value.reason).into())
        }
    };
    sync_write(
        &root.join("authorization.json"),
        &authorization.canonical_bytes()?,
        false,
    )?;
    let report = ledger.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        &key,
        || {
            if cut == Cut::Claimed {
                abort_at(cut);
            }
            sync_write(&root.join("effect.log"), b"effect\n", true)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
            if cut == Cut::Effect {
                abort_at(cut);
            }
            Ok(CallerExecutionReport {
                output: serde_json::json!({"original_native_effect": true, "safe": true}),
                realized_cost: None,
            })
        },
    )?;
    if cut == Cut::Report {
        abort_at(cut);
    }
    match cut {
        Cut::OutputJoined | Cut::OutputJoinedChangedClassification => fixture
            .kernel
            .set_security_pre_dispatch_hook(Arc::new(ProcessHook {
                resolver: resolver(fixture.binding.clone(), disclosure.as_ref())?,
                point: Point::OutputJoined,
            })),
        Cut::Finalization(name) => fixture
            .kernel
            .install_durable_finalization_cutpoint(Arc::new(move |actual| {
                if actual == name.point() {
                    abort_at(cut);
                }
            })),
        _ => {}
    }
    let response = fixture
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    Err(format!(
        "native caller missed {cut:?}: {:?} {:?}",
        response.verdict, response.reason
    )
    .into())
}

fn matrix(name: &str, cut: Cut, combined_disclosure: bool) -> TestResult {
    if std::env::var_os(CHILD).is_some() {
        return execute_child(cut, combined_disclosure);
    }
    let root = tempfile::tempdir()?;
    let output = std::fs::File::create(root.path().join("child.log"))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            &format!(
                "security::adapters::tests::native_flow::support::process_recovery::caller::{name}"
            ),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env(ROOT, root.path())
        .stdout(output.try_clone()?)
        .stderr(output)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(format!("native caller cutpoint timed out: {cut:?}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let log = std::fs::read_to_string(root.path().join("child.log"))?;
    assert_eq!(status.signal(), Some(6), "{cut:?}: {log}");
    let marker = match cut {
        Cut::BeforeCaptureCommit => "native capture transaction cutpoint: BeforeCommit".into(),
        Cut::AfterCaptureCommit => {
            "native capture transaction cutpoint: CommittedBeforeAnchor".into()
        }
        Cut::OutputJoined | Cut::OutputJoinedChangedClassification => {
            "native process cutpoint: OutputJoined".into()
        }
        _ => format!("native caller process cutpoint: {cut:?}"),
    };
    assert!(
        log.lines().any(|line| line.ends_with(&marker)),
        "wrong abort: {log}"
    );
    let witness: Witness =
        serde_json::from_slice(&std::fs::read(root.path().join("witness.json"))?)?;
    assert_eq!(witness.directory.parent(), Some(root.path()));
    verify_restart(root.path(), &witness, cut)
}

fn verify_restart(root: &Path, witness: &Witness, cut: Cut) -> TestResult {
    use chio_kernel::tool_outcome::ToolOutcomeStore;
    let authority = SqliteAuthorityStore::open_serving(
        witness.directory.join("admission.db"),
        witness.directory.join("locks"),
    )?;
    assert!(authority.mutation_fence().owner_epoch > witness.fence.owner_epoch);
    let store = authority.admission_operation_store();
    let (before, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &witness.request.request_id)?,
            &authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("retained native caller")?;
    let id = before.binding().operation_id();
    assert!(store
        .load_retained_tool_request(id, &witness.fence, now_ms()?)
        .is_err());
    let committed = cut != Cut::BeforeCaptureCommit;
    assert_eq!(before.dispatch_commit().is_some(), committed);
    assert_eq!(before.native_dispatch_ledger_digest().is_some(), committed);
    assert_eq!(before.caller_dispatch_context_digest().is_some(), committed);
    let signer = Keypair::from_seed_hex(&witness.signer)?;
    let key = Keypair::from_seed_hex(&std::fs::read_to_string(root.join("executor-key"))?)?;
    let executor = original
        .authority_profile()
        .ok_or("profile")?
        .caller_executor()
        .ok_or("executor pin")?
        .clone();
    let (mut kernel, invocations) = open_kernel(&witness.directory, &authority, &signer)?;
    configure_caller_restart(&mut kernel, &original, witness)?;
    let disclosure = witness
        .declassification_signer
        .as_ref()
        .map(|seed| Keypair::from_seed_hex(seed))
        .transpose()?;
    let changed_classification = cut == Cut::OutputJoinedChangedClassification;
    let output_resolver = if changed_classification {
        let mut config = flow_config();
        config.category_labels = CategoryLabelMap::new(
            ClassifierId::new("classifier.empty")?,
            ClassifierVersion::new("1")?,
            BTreeMap::from([(
                RecordId::new("restricted")?,
                super::super::super::restricted_label(),
            )]),
        )?;
        NativeFlowResolver::new(
            witness.binding.clone(),
            super::super::super::registry(true, InformationLabel::bottom())?,
            Arc::new(super::super::super::RestrictedClassifier),
            Arc::new(Clock::default()),
            config,
        )?
        .with_captured_lifecycle()
    } else {
        resolver(witness.binding.clone(), disclosure.as_ref())?
    };
    let classification_rejections = Arc::new(AtomicUsize::new(0));
    kernel.set_security_pre_dispatch_hook(Arc::new(RecoveryOutput {
        resolver: output_resolver,
        classification_rejections: classification_rejections.clone(),
    }));
    kernel.set_caller_executor(executor.clone())?;
    let recovery = kernel.reconcile_durable_admission_startup();
    if changed_classification {
        assert_eq!(classification_rejections.load(Ordering::SeqCst), 1);
        assert!(matches!(
            recovery,
            Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
        ));
    } else {
        recovery?;
    }
    let quota = authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&witness.request.capability.id, 0))?
        .ok_or("quota history")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (0, u32::from(committed))
    );
    if committed {
        let nonce = witness
            .request
            .execution_nonce
            .as_ref()
            .ok_or("original nonce")?;
        let authorization =
            match kernel.start_caller_execution_blocking(nonce, &witness.request.arguments)? {
                CallerStartResponse::Authorized(value) => *value,
                CallerStartResponse::Denied(value) => {
                    return Err(format!("original authorization denied: {:?}", value.reason).into())
                }
            };
        if cut != Cut::AfterCaptureCommit {
            assert_eq!(
                authorization,
                SignedCallerDispatchAuthorizationV1::from_canonical_bytes(&std::fs::read(
                    root.join("authorization.json")
                )?)?
            );
            let ledger = SqliteCallerExecutionLedger::open(
                &witness.directory.join("executor.db"),
                executor,
            )?;
            let replayed_effects = AtomicUsize::new(0);
            let report = ledger.execute_once(
                &authorization,
                &signer.public_key(),
                &authorization.authorization.invocation,
                &key,
                || {
                    replayed_effects.fetch_add(1, Ordering::SeqCst);
                    Err(KernelError::Internal("must never repeat the effect".into()))
                },
            );
            if cut.reported() {
                let report = report?;
                if changed_classification {
                    for _ in 0..2 {
                        assert!(kernel
                            .reconcile_authenticated_caller_execution_blocking(
                                &authorization,
                                &report
                            )
                            .is_err());
                    }
                    assert!(authority
                        .tool_outcome_store()
                        .lookup_security_release(id)?
                        .is_none());
                } else {
                    let completed = kernel.reconcile_authenticated_caller_execution_blocking(
                        &authorization,
                        &report,
                    )?;
                    assert_eq!(
                        completed.verdict,
                        Verdict::Allow,
                        "{cut:?}: {:?}",
                        completed.reason
                    );
                    assert!(completed.receipt.verify_signature()?);
                    assert!(
                        matches!(&completed.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &report.report.output)
                    );
                    let duplicate = kernel.reconcile_authenticated_caller_execution_blocking(
                        &authorization,
                        &report,
                    )?;
                    assert_eq!(
                        chio_core::canonical_json_bytes(&completed.receipt)?,
                        chio_core::canonical_json_bytes(&duplicate.receipt)?
                    );
                    assert!(authority
                        .tool_outcome_store()
                        .lookup_security_release(id)?
                        .is_some());
                }
            } else {
                assert!(matches!(
                    report,
                    Err(CallerExecutionLedgerError::OutcomeUnknown)
                ));
                assert_eq!(
                    store
                        .load_by_operation_id(id)?
                        .ok_or("waiting operation")?
                        .state(),
                    AdmissionOperationState::AwaitingCallerReport
                );
                assert!(authority
                    .tool_outcome_store()
                    .lookup_security_release(id)?
                    .is_none());
            }
            assert_eq!(replayed_effects.load(Ordering::SeqCst), 0);
        }
    }
    let effects = match std::fs::read_to_string(root.join("effect.log")) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    assert_eq!(effects, if cut.effected() { "effect\n" } else { "" });
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

// Preserve production error redaction while retaining useful failure context in
// this disposable process harness. This hook can neither admit nor dispatch.
struct RecoveryOutput {
    resolver: NativeFlowResolver,
    classification_rejections: Arc<AtomicUsize>,
}

impl SecurityPreDispatchHook for RecoveryOutput {
    fn name(&self) -> &str {
        "native-caller-recovery-output"
    }
    fn supports_native_dispatch(&self) -> bool {
        true
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.resolver.native_authority_binding()
    }
    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        let result = self.resolver.prepare_native_output(context, authority);
        if let Err(error) = &result {
            if error.to_string().contains(
                "native caller output replay changed its original classification or identity",
            ) {
                self.classification_rejections
                    .fetch_add(1, Ordering::SeqCst);
            }
            eprintln!("native caller recovery output: {error}");
        }
        result
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::GuardDenied("recovery cannot dispatch".into()))
    }
}

macro_rules! caller_case {
    ($name:ident, $cut:expr, $combined:expr) => {
        #[test]
        fn $name() -> TestResult {
            matrix(stringify!($name), $cut, $combined)
        }
    };
}
caller_case!(
    native_caller_abort_before_atomic_capture,
    Cut::BeforeCaptureCommit,
    false
);
caller_case!(
    native_caller_abort_after_atomic_capture,
    Cut::AfterCaptureCommit,
    false
);
caller_case!(
    native_caller_abort_after_claim_before_effect,
    Cut::Claimed,
    false
);
caller_case!(
    native_caller_abort_after_effect_without_report,
    Cut::Effect,
    false
);
caller_case!(native_caller_abort_after_durable_report, Cut::Report, false);
caller_case!(
    native_caller_abort_after_raw_report,
    Cut::Finalization(FinalizationName::Returned),
    false
);
caller_case!(
    native_caller_abort_after_output_join,
    Cut::OutputJoined,
    false
);
caller_case!(
    native_caller_output_recovery_rejects_changed_classification,
    Cut::OutputJoinedChangedClassification,
    false
);
caller_case!(
    native_caller_abort_after_release_acknowledgement,
    Cut::Finalization(FinalizationName::Acknowledged),
    false
);
caller_case!(
    native_caller_abort_after_release_checkpoint,
    Cut::Finalization(FinalizationName::Checkpointed),
    false
);
caller_case!(
    native_caller_abort_after_terminal_projection,
    Cut::Finalization(FinalizationName::Terminal),
    false
);
caller_case!(
    native_caller_combined_disclosure_abort_after_report,
    Cut::Report,
    true
);
caller_case!(
    native_caller_combined_disclosure_abort_after_release,
    Cut::Finalization(FinalizationName::Acknowledged),
    true
);
