use super::*;

use std::sync::{atomic::AtomicUsize, Arc};

struct RejectFirstOutputGuard {
    validations: Arc<AtomicUsize>,
    panic_on_rejection: bool,
}

impl Guard for RejectFirstOutputGuard {
    fn name(&self) -> &str {
        "reject-first-output"
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn output_rejection_is_zero_charge(&self, _: &GuardContext<'_>) -> bool {
        true
    }

    fn validate_output_before_release(
        &self,
        _: &GuardContext<'_>,
        _: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        if self.validations.fetch_add(1, Ordering::SeqCst) == 0 {
            assert!(!self.panic_on_rejection, "private first-check panic");
            return Err(KernelError::GuardDenied(
                "private first-check rejection".into(),
            ));
        }
        Ok(())
    }
}

struct RejectSecondOrdinaryOutputGuard {
    validations: AtomicUsize,
}

impl Guard for RejectSecondOrdinaryOutputGuard {
    fn name(&self) -> &str {
        "reject-second-ordinary-output"
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn validate_output_before_release(
        &self,
        _: &GuardContext<'_>,
        _: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        if self.validations.fetch_add(1, Ordering::SeqCst) == 1 {
            return Err(KernelError::GuardDenied(
                "temporary ordinary output rejection".into(),
            ));
        }
        Ok(())
    }
}

struct TemporarilyBlockingDurableHook {
    inspections: AtomicUsize,
}

impl crate::post_invocation::PostInvocationHook for TemporarilyBlockingDurableHook {
    fn name(&self) -> &str {
        "temporarily-blocking-durable-hook"
    }

    fn inspect(
        &self,
        _: &crate::post_invocation::PostInvocationContext<'_>,
        _: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        if self.inspections.fetch_add(1, Ordering::SeqCst) == 0 {
            crate::post_invocation::PostInvocationVerdict::Block(
                "injected non-blocking contract violation".into(),
            )
        } else {
            crate::post_invocation::PostInvocationVerdict::Allow
        }
    }

    fn durable_identity(
        &self,
    ) -> Result<Option<crate::post_invocation::PostInvocationHookIdentity>, String> {
        crate::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            self.name(),
            "1",
            "chio-kernel.tests.temporary-output-preparation-failure.v1",
            &(),
        )
        .map(Some)
    }
}

#[derive(Clone, Copy)]
enum OutputPreparationFailure {
    None,
    OrdinaryGuard,
    PostInvocation,
}

fn assert_first_checked_output_rejection_is_retained(
    panic_on_rejection: bool,
    fail_projection: bool,
    preparation_failure: OutputPreparationFailure,
) {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".into(),
    });
    grant.max_total_cost = grant.max_cost_per_invocation.clone();
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture_with_grants("checked-output-first-rejection", vec![grant]);
    let validations = Arc::new(AtomicUsize::new(0));
    kernel.add_guard(Box::new(RejectFirstOutputGuard {
        validations: validations.clone(),
        panic_on_rejection,
    }));
    match preparation_failure {
        OutputPreparationFailure::None => {}
        OutputPreparationFailure::OrdinaryGuard => {
            kernel.add_guard(Box::new(RejectSecondOrdinaryOutputGuard {
                validations: AtomicUsize::new(0),
            }));
        }
        OutputPreparationFailure::PostInvocation => {
            kernel.add_post_invocation_hook(Box::new(TemporarilyBlockingDurableHook {
                inspections: AtomicUsize::new(0),
            }));
        }
    }
    let actions = Arc::new(std::sync::Mutex::new(Vec::new()));
    kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
        authorization_references: Default::default(),
        settlement_actions: actions.clone(),
        settlement_references: Default::default(),
    }));
    if !matches!(preparation_failure, OutputPreparationFailure::None) {
        let error = kernel
            .evaluate_tool_call_blocking(&request)
            .expect_err("output preparation temporarily refuses release");
        match preparation_failure {
            OutputPreparationFailure::OrdinaryGuard => assert!(matches!(
                error,
                KernelError::GuardDenied(ref reason)
                    if reason.contains("temporary ordinary output rejection")
            )),
            OutputPreparationFailure::PostInvocation => assert!(matches!(
                error,
                KernelError::DurableAdmission(ref reason)
                    if reason.contains("violated its non-blocking contract")
            )),
            OutputPreparationFailure::None => unreachable!("preparation failure selected"),
        }
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::Finalizing
        );
        assert!(actions.lock().expect("no premature settlement").is_empty());
    }
    if fail_projection {
        store.fail_next_terminal_projection();
        let error = kernel
            .evaluate_tool_call_blocking(&request)
            .expect_err("injected projection failure");
        assert!(matches!(
            error,
            KernelError::DurableAdmission(ref reason)
                if reason.contains("injected terminal projection failure")
        ));
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::Finalizing
        );
    }
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("retain the first contractual rejection");
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature().expect("signature"));
    assert_eq!(
        response.receipt.content_hash,
        sha256_hex(crate::admission_operation::OUTPUT_GUARD_REJECTION_REDACTION_DOMAIN)
    );
    assert!(!serde_json::to_string(&response.receipt)
        .expect("receipt")
        .contains("private first-check"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DeniedAfterDelivery
    );
    assert_eq!(*actions.lock().expect("actions"), vec!["release"]);
    assert_eq!(validations.load(Ordering::SeqCst), 2);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("later checker acceptance cannot upgrade the denial");
    assert_same_receipt(&response.receipt, &replay.receipt);
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay.output.is_none());
    assert_eq!(validations.load(Ordering::SeqCst), 2);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(*actions.lock().expect("actions"), vec!["release"]);
}

#[test]
fn checked_output_first_rejection_is_not_upgraded_by_later_acceptance() {
    assert_first_checked_output_rejection_is_retained(false, false, OutputPreparationFailure::None);
}

#[test]
fn checked_output_first_panic_is_not_upgraded_by_later_acceptance() {
    assert_first_checked_output_rejection_is_retained(true, false, OutputPreparationFailure::None);
}

#[test]
fn checked_output_first_rejection_survives_terminal_projection_recovery() {
    assert_first_checked_output_rejection_is_retained(false, true, OutputPreparationFailure::None);
}

#[test]
fn checked_output_first_rejection_is_not_upgraded_after_later_guard_failure() {
    assert_first_checked_output_rejection_is_retained(
        false,
        false,
        OutputPreparationFailure::OrdinaryGuard,
    );
}

#[test]
fn checked_output_first_panic_is_not_upgraded_after_later_guard_failure() {
    assert_first_checked_output_rejection_is_retained(
        true,
        false,
        OutputPreparationFailure::OrdinaryGuard,
    );
}

#[test]
fn checked_output_first_rejection_is_not_upgraded_after_post_invocation_failure() {
    assert_first_checked_output_rejection_is_retained(
        false,
        false,
        OutputPreparationFailure::PostInvocation,
    );
}

#[test]
fn checked_output_first_panic_is_not_upgraded_after_post_invocation_failure() {
    assert_first_checked_output_rejection_is_retained(
        true,
        false,
        OutputPreparationFailure::PostInvocation,
    );
}

struct CheckedOutputGuard {
    allow: std::sync::Arc<std::sync::atomic::AtomicBool>,
    contract: bool,
    panic: bool,
}

impl Guard for CheckedOutputGuard {
    fn name(&self) -> &str {
        "checked-output-test"
    }
    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }
    fn output_rejection_is_zero_charge(&self, _: &GuardContext<'_>) -> bool {
        self.contract
    }
    fn validate_output_before_release(
        &self,
        _: &GuardContext<'_>,
        _: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        assert!(!self.panic, "injected checker panic");
        if self.allow.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(KernelError::GuardDenied("private checker detail".into()))
        }
    }
}

#[test]
fn checked_output_rejection_releases_only_its_hold_and_never_upgrades_on_replay() {
    for panic in [false, true] {
        let mut grant = make_grant("durable-server", "mutate");
        grant.max_invocations = Some(1);
        grant.max_cost_per_invocation = Some(MonetaryAmount {
            units: 10,
            currency: "USD".into(),
        });
        grant.max_total_cost = Some(MonetaryAmount {
            units: 10,
            currency: "USD".into(),
        });
        let (mut kernel, request, store, invocations) =
            durable_admission_fixture_with_grants("checked-output-terminal", vec![grant]);
        let allow = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        kernel.add_guard(Box::new(CheckedOutputGuard {
            allow: allow.clone(),
            contract: true,
            panic,
        }));
        let actions = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
            authorization_references: Default::default(),
            settlement_actions: actions.clone(),
            settlement_references: Default::default(),
        }));
        let response = kernel
            .evaluate_tool_call_blocking(&request)
            .expect("signed rejection");
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert!(response.output.is_none());
        assert!(response.receipt.verify_signature().expect("signature"));
        assert_eq!(
            response.receipt.content_hash,
            sha256_hex(crate::admission_operation::OUTPUT_GUARD_REJECTION_REDACTION_DOMAIN)
        );
        assert!(!serde_json::to_string(&response.receipt)
            .expect("receipt")
            .contains("private checker detail"));
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::DeniedAfterDelivery
        );
        assert_eq!(*actions.lock().expect("actions"), vec!["release"]);
        allow.store(true, Ordering::SeqCst);
        let replay = kernel
            .evaluate_tool_call_blocking(&request)
            .expect("retained rejection");
        assert_same_receipt(&response.receipt, &replay.receipt);
        assert_eq!(replay.verdict, Verdict::Deny);
        assert!(replay.output.is_none());
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(actions.lock().expect("actions").len(), 1);
    }
}

#[test]
fn ordinary_output_rejection_has_no_zero_charge_authority() {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".into(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 10,
        currency: "USD".into(),
    });
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture_with_grants("ordinary-output-rejection", vec![grant]);
    let actions = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
        authorization_references: Default::default(),
        settlement_actions: actions.clone(),
        settlement_references: Default::default(),
    }));
    kernel.add_guard(Box::new(CheckedOutputGuard {
        allow: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        contract: false,
        panic: false,
    }));
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("ordinary guard stays fail-closed");
    assert!(error.to_string().contains("private checker detail"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(actions.lock().expect("no settlement actions").is_empty());
    assert_eq!(
        store.payment_journal().expect("retained hold").state,
        crate::payment::PaymentJournalState::Authorized
    );
}

#[test]
fn checked_output_contract_cannot_mix_with_digest_delivery() {
    let mut grant = make_grant("durable-server", "mutate");
    grant
        .constraints
        .push(Constraint::OutputDigestSha256(sha256_hex(b"output")));
    let (mut kernel, request, _store, invocations) =
        durable_admission_fixture_with_grants("checked-output-mixed-contract", vec![grant]);
    kernel.add_guard(Box::new(CheckedOutputGuard {
        allow: Default::default(),
        contract: true,
        panic: false,
    }));
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("deny unsupported combination");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("cannot combine")));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}
