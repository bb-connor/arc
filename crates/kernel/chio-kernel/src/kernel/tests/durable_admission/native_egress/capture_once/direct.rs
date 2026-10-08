//! A host can retain custody through the public preparation handle before it
//! enters the capture authority. The authority reads back the original
//! operation's egress history: a committed fence keeps any later failure
//! unconfirmed, an acquisition alone is still a definite rejection, and an
//! unreadable history is never reported as a definite rejection.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Retention {
    /// Public retention commits egress and the ledger; capture then refuses
    /// the undated policy before entering the store.
    CommittedThenCaptureRefused,
    /// The egress commitment is written but its acknowledgement is lost.
    CommitAcknowledgementLost,
    /// Acquisition succeeds and the store refuses the commitment.
    AcquiredCommitRefused,
    /// Ledger-only retention; capture refuses the undated policy and the
    /// egress history cannot be read back.
    LedgerWithUnreadableHistory,
}

impl Retention {
    fn unconfirmed(self) -> bool {
        !matches!(self, Self::AcquiredCommitRefused)
    }
}

struct DirectHook {
    binding: NativeSecurityAuthorityBindingV1,
    store: Arc<TestAdmissionOperationStore>,
    retention: Retention,
    egress_until: u64,
    undated_policy: Vec<u8>,
    callbacks: AtomicU64,
    attempts: Mutex<Vec<Attempt>>,
}

impl DirectHook {
    fn retain_and_capture(
        &self,
        authority: &mut NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        let grant_index = authority.grant_index()?;
        let prepared = authority.prepare_egress()?;
        let (prepared, ledger) = match self.retention {
            Retention::CommittedThenCaptureRefused => {
                let retained = prepared.retain_for_capture(
                    Some(self.egress_until),
                    grant_index,
                    &self.undated_policy,
                );
                self.record(attempt(&retained))?;
                let (prepared, _, ledger) = retained?;
                (prepared, ledger)
            }
            Retention::CommitAcknowledgementLost | Retention::AcquiredCommitRefused => {
                let acquired = prepared.acquire(self.egress_until)?;
                let fault = match self.retention {
                    Retention::CommitAcknowledgementLost => Fault::LostAck,
                    _ => Fault::Deny,
                };
                self.store
                    .native_egress
                    .arm_commit(fault)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
                let committed = acquired.commit();
                self.record(attempt(&committed))?;
                committed?;
                return Err(KernelError::Internal(
                    "direct egress commitment unexpectedly succeeded".into(),
                ));
            }
            Retention::LedgerWithUnreadableHistory => {
                let retained = prepared.retain_for_capture(None, grant_index, &self.undated_policy);
                self.record(attempt(&retained))?;
                let (prepared, _, ledger) = retained?;
                self.store
                    .native_egress
                    .arm(Fault::PanicRead)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
                (prepared, ledger)
            }
        };
        let captured = authority.capture(prepared, &ledger, &self.undated_policy);
        self.record(attempt(&captured))?;
        captured.map(|_| ())
    }

    fn record(&self, attempt: Attempt) -> Result<(), KernelError> {
        self.attempts.lock().map_err(poisoned)?.push(attempt);
        Ok(())
    }
}

impl SecurityPreDispatchHook for DirectHook {
    fn name(&self) -> &str {
        "native-direct-retention"
    }

    fn supports_native_dispatch(&self) -> bool {
        true
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
        super::super::super::native_acquisition::join(authority).map(|_| ())
    }

    fn commit_native_dispatch(
        &self,
        authority: &mut NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        self.retain_and_capture(authority)
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "native custody entered legacy dispatch".into(),
        ))
    }
}

struct Direct {
    kernel: ChioKernel,
    request: ToolCallRequest,
    context: SecurityInvocationContext,
    store: Arc<TestAdmissionOperationStore>,
    invocations: Arc<AtomicU64>,
    hook: Arc<DirectHook>,
}

fn arrange(retention: Retention) -> CaptureResult<Direct> {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (mut kernel, request, store, invocations) = durable_admission_fixture_with_grants(
        &format!("native-direct-retention-{retention:?}"),
        vec![grant],
    );
    let hook = Arc::new(DirectHook {
        binding: NativeSecurityAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("store", "native-store")?,
            AdmissionIdentifier::try_new("authority", "native-authority")?,
            AdmissionDigest::try_new("initialization", sha256_hex(b"native-init"))?,
        ),
        store: store.clone(),
        retention,
        egress_until: current_unix_timestamp_ms() + 60_000,
        undated_policy: canonical_json_bytes(&serde_json::json!({
            "schema": POLICY_SCHEMA,
            "inputs": {},
        }))?,
        callbacks: AtomicU64::new(0),
        attempts: Mutex::new(Vec::new()),
    });
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(hook.clone());
    kernel.set_durable_admission_store(
        store.clone(),
        Arc::new(ReleaseReadyOutcomes(store.clone())),
        admission_test_fence(),
    )?;
    store.native_egress.enable(7)?;
    let context = security_binding::context(&request, 1)?;
    Ok(Direct {
        kernel,
        request,
        context,
        store,
        invocations,
        hook,
    })
}

#[derive(Clone, Debug, PartialEq)]
struct Custody {
    state: AdmissionOperationState,
    hold: BudgetHoldDispositionView,
    quota: (u32, u32),
    egress_committed: Option<bool>,
    ledger: bool,
}

fn custody(case: &Direct) -> CaptureResult<Custody> {
    let operation = case.store.operation();
    assert!(operation.dispatch_commit().is_none());
    let hold = case
        .store
        .budget_store()
        .get_budget_hold(
            operation
                .budget_hold_id()
                .ok_or("native operation lost its hold")?
                .as_str(),
        )?
        .ok_or("native operation hold is absent")?
        .disposition;
    let usage = case
        .store
        .budget_store()
        .get_invocation_quota_usage(&crate::budget_store::BudgetQuotaKey::grant(
            &case.request.capability.id,
            0,
        ))?
        .ok_or("native operation quota is absent")?;
    let fence = case
        .store
        .fence
        .lock()
        .map_err(|_| "admission fence poisoned")?
        .clone();
    let id = operation.binding().operation_id();
    let now = current_unix_timestamp_ms();
    let egress_committed =
        crate::admission_operation::AdmissionOperationStore::load_native_security_egress(
            case.store.as_ref(),
            id,
            &fence,
            now,
        )?
        .ok_or("native operation egress read is absent")?
        .1
        .map(|history| history.commitment.is_some());
    let ledger = crate::admission_operation::AdmissionOperationStore::load_native_dispatch_ledger(
        case.store.as_ref(),
        id,
        &fence,
        now,
    )?
    .is_some();
    Ok(Custody {
        state: operation.state(),
        hold,
        quota: (usage.reserved_invocations, usage.captured_invocations),
        egress_committed,
        ledger,
    })
}

fn direct_retention(retention: Retention) -> CaptureResult {
    let label = format!("{retention:?}");
    let case = arrange(retention)?;
    let denied = case
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&case.request, &case.context)?;
    case.store.native_egress.arm(Fault::None)?;
    let attempts = match retention {
        Retention::CommittedThenCaptureRefused | Retention::LedgerWithUnreadableHistory => vec![
            Attempt::Captured,
            Attempt::Refused(DEADLINE_REFUSAL.into()),
        ],
        Retention::CommitAcknowledgementLost => vec![Attempt::Other(
            "durable admission failed: admission operation durable outcome is unknown: injected lost acknowledgement".into(),
        )],
        Retention::AcquiredCommitRefused => vec![Attempt::Other(
            "durable admission failed: admission operation invariant failed: injected write denial".into(),
        )],
    };
    assert_eq!(
        *case
            .hook
            .attempts
            .lock()
            .map_err(|_| "attempt record poisoned")?,
        attempts,
        "{label}"
    );
    assert_eq!(denied.verdict, Verdict::Deny, "{label}: {denied:?}");
    assert_eq!(
        denied.reason.as_deref(),
        Some(
            KernelError::SecurityDispatchOutcomeRecoveryRequired(
                "security native dispatch capture callback failed; authoritative recovery required"
                    .into(),
            )
            .to_string()
            .as_str()
        ),
        "{label}"
    );
    assert!(denied.output.is_none(), "{label}");
    assert!(denied.receipt.verify_signature()?, "{label}");
    let (egress_committed, ledger) = match retention {
        Retention::CommittedThenCaptureRefused => (Some(true), true),
        Retention::CommitAcknowledgementLost => (Some(true), false),
        Retention::AcquiredCommitRefused => (Some(false), false),
        Retention::LedgerWithUnreadableHistory => (None, true),
    };
    let compensated = Custody {
        state: AdmissionOperationState::CompensatedBeforeDispatch,
        hold: BudgetHoldDispositionView::Reversed,
        quota: (0, 0),
        egress_committed,
        ledger,
    };
    let (after, replay_reason) = if retention.unconfirmed() {
        (
            Custody {
                state: AdmissionOperationState::CapturePending,
                hold: BudgetHoldDispositionView::Open,
                quota: (1, 0),
                ..compensated.clone()
            },
            "native preparation requires original pre-budget authority",
        )
    } else {
        (
            compensated.clone(),
            "request replay is retained in state CompensatedBeforeDispatch",
        )
    };
    assert_eq!(custody(&case)?, after, "{label}");

    let replay = case
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&case.request, &case.context)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{label}: {replay:?}");
    assert_eq!(
        replay.reason.as_deref(),
        Some(
            KernelError::DurableAdmission(replay_reason.into())
                .to_string()
                .as_str()
        ),
        "{label}"
    );
    assert!(replay.output.is_none(), "{label}");
    // Recovery keeps retained custody and never re-enters the host hook.
    assert_eq!(custody(&case)?, compensated, "{label}");
    assert_eq!(case.hook.callbacks.load(Ordering::SeqCst), 1, "{label}");
    assert_eq!(case.invocations.load(Ordering::SeqCst), 0, "{label}");
    Ok(())
}

#[test]
fn native_direct_retention_is_classified_by_committed_egress_readback() -> CaptureResult {
    for retention in [
        Retention::CommittedThenCaptureRefused,
        Retention::CommitAcknowledgementLost,
        Retention::AcquiredCommitRefused,
        Retention::LedgerWithUnreadableHistory,
    ] {
        direct_retention(retention)?;
    }
    Ok(())
}
