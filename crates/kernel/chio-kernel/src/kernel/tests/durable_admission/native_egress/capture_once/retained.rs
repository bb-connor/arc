//! Authority-owned retention checks live custody before its first durable
//! write. A failure before that write is a definite rejection without custody;
//! any later failure stays unconfirmed with the hold, egress and ledger kept.
use super::*;
use crate::admission_operation::AdmissionOperationStore;
use crate::kernel::tests::durable_admission::recovery_lease::Stage;

const LEASE_FAILURE: &str = "durable admission failed: admission operation durable outcome is unknown: recovery lease qualification callback panicked";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    PreWriteLease,
    PreWriteDeadline,
    PostWriteLease,
    PostWriteDeadline,
}

impl Fault {
    fn after_retention(self) -> bool {
        matches!(self, Self::PostWriteLease | Self::PostWriteDeadline)
    }
}

struct RetainingHook {
    binding: NativeSecurityAuthorityBindingV1,
    store: Arc<TestAdmissionOperationStore>,
    fault: Fault,
    egress_until: Option<u64>,
    policy: Vec<u8>,
    undated_policy: Vec<u8>,
    callbacks: AtomicU64,
    attempts: Mutex<Vec<Attempt>>,
}

impl RetainingHook {
    fn retain_and_capture(
        &self,
        authority: &mut NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        if self.fault == Fault::PreWriteLease {
            self.store.recovery_lease_faults.arm(Stage::ClaimBefore);
        }
        let retained_policy = match self.fault {
            Fault::PreWriteDeadline => &self.undated_policy,
            _ => &self.policy,
        };
        let prepared = authority.prepare_egress()?;
        let retained =
            authority.retain_for_capture(prepared, self.egress_until, retained_policy, None);
        self.record(attempt(&retained))?;
        let (prepared, egress, ledger) = retained?;
        if egress.is_some() != self.egress_until.is_some() {
            return Err(KernelError::Internal(
                "authority retention changed the egress selection".into(),
            ));
        }
        if self.fault == Fault::PostWriteLease {
            self.store.recovery_lease_faults.arm(Stage::ClaimBefore);
        }
        let capture_policy = match self.fault {
            Fault::PostWriteDeadline => &self.undated_policy,
            _ => &self.policy,
        };
        let captured = authority.capture(prepared, &ledger, capture_policy);
        self.record(attempt(&captured))?;
        captured.map(|_| ())
    }

    fn record(&self, attempt: Attempt) -> Result<(), KernelError> {
        self.attempts.lock().map_err(poisoned)?.push(attempt);
        Ok(())
    }
}

impl SecurityPreDispatchHook for RetainingHook {
    fn name(&self) -> &str {
        "native-retaining-capture"
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
        let result = self.retain_and_capture(authority);
        // Neither a spare preparation nor a second retention can reopen custody.
        let again = authority.prepare_egress().and_then(|spare| {
            authority.retain_for_capture(spare, self.egress_until, &self.policy, None)
        });
        self.record(attempt(&again))?;
        result
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

fn policy(inputs: serde_json::Value) -> CaptureResult<Vec<u8>> {
    Ok(canonical_json_bytes(&serde_json::json!({
        "schema": POLICY_SCHEMA,
        "inputs": inputs,
    }))?)
}

struct Retained {
    kernel: ChioKernel,
    request: ToolCallRequest,
    context: SecurityInvocationContext,
    store: Arc<TestAdmissionOperationStore>,
    invocations: Arc<AtomicU64>,
    hook: Arc<RetainingHook>,
}

fn arrange(fault: Fault, egress: bool) -> CaptureResult<Retained> {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (mut kernel, request, store, invocations) = durable_admission_fixture_with_grants(
        &format!("native-retained-capture-{fault:?}-{egress}"),
        vec![grant],
    );
    let valid_until = current_unix_timestamp_ms() + 60_000;
    let hook = Arc::new(RetainingHook {
        binding: NativeSecurityAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("store", "native-store")?,
            AdmissionIdentifier::try_new("authority", "native-authority")?,
            AdmissionDigest::try_new("initialization", sha256_hex(b"native-init"))?,
        ),
        store: store.clone(),
        fault,
        egress_until: egress.then_some(valid_until),
        policy: policy(serde_json::json!({ "valid_until_unix_ms": valid_until }))?,
        undated_policy: policy(serde_json::json!({}))?,
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
    Ok(Retained {
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

fn custody(case: &Retained) -> CaptureResult<Custody> {
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
        AdmissionOperationStore::load_native_security_egress(case.store.as_ref(), id, &fence, now)?
            .ok_or("native operation egress read is absent")?
            .1
            .map(|history| history.commitment.is_some());
    let ledger =
        AdmissionOperationStore::load_native_dispatch_ledger(case.store.as_ref(), id, &fence, now)?
            .is_some();
    Ok(Custody {
        state: operation.state(),
        hold,
        quota: (usage.reserved_invocations, usage.captured_invocations),
        egress_committed,
        ledger,
    })
}

fn retained_capture(fault: Fault, egress: bool) -> CaptureResult {
    let label = format!("{fault:?}/egress={egress}");
    let case = arrange(fault, egress)?;
    let denied = case
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&case.request, &case.context)?;
    let failure = match fault {
        Fault::PreWriteLease | Fault::PostWriteLease => Attempt::Other(LEASE_FAILURE.into()),
        Fault::PreWriteDeadline | Fault::PostWriteDeadline => {
            Attempt::Refused(DEADLINE_REFUSAL.into())
        }
    };
    let refused_again = Attempt::Refused(ALREADY_ATTEMPTED.into());
    let attempts = if fault.after_retention() {
        vec![Attempt::Captured, failure, refused_again]
    } else {
        vec![failure, refused_again]
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
    let compensated = Custody {
        state: AdmissionOperationState::CompensatedBeforeDispatch,
        hold: BudgetHoldDispositionView::Reversed,
        quota: (0, 0),
        egress_committed: None,
        ledger: false,
    };
    let (after, replay_reason, replayed) = if fault.after_retention() {
        let retained = Custody {
            egress_committed: egress.then_some(true),
            ledger: true,
            ..compensated
        };
        (
            Custody {
                state: AdmissionOperationState::CapturePending,
                hold: BudgetHoldDispositionView::Open,
                quota: (1, 0),
                ..retained.clone()
            },
            "native preparation requires original pre-budget authority",
            retained,
        )
    } else {
        (
            compensated.clone(),
            "request replay is retained in state CompensatedBeforeDispatch",
            compensated,
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
    // Recovery keeps retained custody and never re-enters retention.
    assert_eq!(custody(&case)?, replayed, "{label}");
    assert_eq!(case.hook.callbacks.load(Ordering::SeqCst), 1, "{label}");
    assert_eq!(case.invocations.load(Ordering::SeqCst), 0, "{label}");
    Ok(())
}

#[test]
fn native_authority_retention_classifies_failures_by_first_durable_write() -> CaptureResult {
    for fault in [
        Fault::PreWriteLease,
        Fault::PreWriteDeadline,
        Fault::PostWriteLease,
        Fault::PostWriteDeadline,
    ] {
        for egress in [false, true] {
            retained_capture(fault, egress)?;
        }
    }
    Ok(())
}
