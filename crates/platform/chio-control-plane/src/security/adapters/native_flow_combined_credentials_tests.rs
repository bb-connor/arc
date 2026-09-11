// Complete original credential selection through real native SQLite capture.
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent,
};
use chio_kernel::admission_operation::governed_approval_claim::{
    GovernedApprovalAuthorityBindingV1, GovernedApprovalClaimDisposition,
};
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantDisposition;

mod runtime_fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_runtime_fixture.rs"
    ));
}

mod nested {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_nested_credentials_tests.rs"
    ));
}

impl Fixture {
    fn configure_native_capture_approval(&mut self) -> TestResult {
        let path = self._directory.path().join("native-approval.db");
        drop(chio_store_sqlite::SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 16)?);
        let source = Arc::new(chio_store_sqlite::SqliteGovernedApprovalReplaySource::open(
            &path,
        )?);
        let store = self.authority.admission_operation_store();
        let fence = self.authority.mutation_fence();
        let authority = AdmissionIdentifier::try_new("authority", "native-combined-approval")?;
        let expected = store.expect_governed_approval_replay_source(
            &AdmissionIdentifier::try_new("source", "native-combined-approval-source")?,
            &authority,
            source.as_ref(),
            &fence,
            now_ms()?,
        )?;
        let imported = store.import_governed_approval_replay_source(
            &authority,
            expected.expectation_id(),
            source.as_ref(),
            &fence,
            now_ms()?,
        )?;
        let binding =
            GovernedApprovalAuthorityBindingV1::new(authority, imported.expectation_id().clone());
        store.activate_governed_approval_replay_source(
            &binding,
            source.as_ref(),
            &fence,
            now_ms()?,
        )?;
        self.kernel
            .set_operation_owned_governed_approval_source(binding, source)?;
        let intent = self
            .request
            .governed_intent
            .as_ref()
            .ok_or("runtime governed intent")?;
        let now = now_ms()? / 1000;
        self.request.approval_token = Some(GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("approval-{}", self.request.request_id),
                approver: self.signer.public_key(),
                subject: self.request.capability.subject.clone(),
                governed_intent_hash: intent.binding_hash()?,
                request_id: self.request.request_id.clone(),
                threshold_proposal_hash: None,
                issued_at: now,
                expires_at: now + 120,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.signer,
        )?);
        Ok(())
    }

    fn combined_native_credentials() -> TestResult<Self> {
        let mut fixture = Self::new_with_credential_profile(
            std::array::from_fn(|_| InformationLabel::bottom()),
            |_| Ok(None),
            true,
            true,
        )?;
        runtime_fixture::install(&mut fixture)?;
        fixture.configure_native_capture_approval()?;
        fixture.configure_native_capture_dpop()?;
        Ok(fixture)
    }
}

#[test]
fn native_capture_preserves_nonempty_runtime_approval_and_dpop_in_one_operation() -> TestResult {
    for egress in [false, true] {
        let mut fixture = Fixture::combined_native_credentials()?;
        let ledger = run_capture(&mut fixture, egress)?;
        assert_combined_capture(fixture, &ledger)?;
    }
    Ok(())
}

fn assert_combined_capture(
    fixture: Fixture,
    ledger: &chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1,
) -> TestResult {
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (_, runtime) = store
        .load_runtime_participant_history(&ledger.operation_id, &fence, now_ms()?)?
        .ok_or("runtime history")?;
    let (_, approval) = store
        .load_governed_approval_claim_history(&ledger.operation_id, &fence, now_ms()?)?
        .ok_or("approval history")?;
    let (_, dpop) = store
        .load_dpop_replay_claim_history(&ledger.operation_id, &fence, now_ms()?)?
        .ok_or("DPoP history")?;
    assert_eq!((runtime.len(), approval.len(), dpop.len()), (1, 1, 1));
    assert_eq!(runtime[0].intent.resources().len(), 1);
    assert_eq!(
        runtime[0].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    assert_eq!(
        approval[0].disposition,
        GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
    );
    assert_eq!(dpop[0].disposition, chio_kernel::admission_operation::dpop_claim::DpopReplayClaimDisposition::RetainedAfterDispatchCommit);
    assert_eq!(runtime[0].intent.grant_index(), 0);
    assert_eq!(approval[0].intent.grant_index(), 0);
    assert_eq!(dpop[0].intent.grant_index(), 0);
    drop(store);
    assert_eq!(
        fixture.reopen_dispatch_ledger(&ledger.operation_id, |_| Ok(()))?,
        *ledger
    );
    Ok(())
}

#[test]
fn native_combined_credentials_deny_missing_proof_or_changed_approved_intent_before_capture(
) -> TestResult {
    for remove_dpop in [false, true] {
        let mut fixture = Fixture::combined_native_credentials()?;
        if remove_dpop {
            fixture.request.dpop_proof = None;
        } else {
            fixture
                .request
                .governed_intent
                .as_mut()
                .ok_or("intent")?
                .purpose = "substituted intent".into();
        }
        let resolver = Arc::new(NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            flow_config(),
        )?);
        fixture.kernel.set_security_pre_dispatch_hook(resolver);
        let capture_calls = Arc::new(AtomicUsize::new(0));
        fixture
            .kernel
            .install_native_capture_checkpoint_hook(Arc::new({
                let calls = capture_calls.clone();
                move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(KernelError::Internal("unexpected capture".into()))
                }
            }));
        let response = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert!(
            response.reason.as_deref().is_some_and(|reason| reason
                .to_ascii_lowercase()
                .contains(if remove_dpop { "dpop" } else { "intent" })),
            "wrong denial: {:?}",
            response.reason
        );
        assert!(response.output.is_none());
        assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        if let Some(usage) = fixture
            .authority
            .budget_store()
            .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        {
            assert_eq!(
                (usage.reserved_invocations, usage.captured_invocations),
                (0, 0)
            );
        }
    }
    Ok(())
}
