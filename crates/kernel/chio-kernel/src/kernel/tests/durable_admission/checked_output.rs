use super::*;

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
        AdmissionOperationState::Finalizing
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
