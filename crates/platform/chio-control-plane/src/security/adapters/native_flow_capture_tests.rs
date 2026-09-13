// Exercise production capture with the real evaluation, policy and SQLite hold.
use super::*;

mod output {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_output_tests.rs"
    ));
}

mod combined_credentials {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_combined_credentials_tests.rs"
    ));
}

mod acknowledgements {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_capture_ack_tests.rs"
    ));
}

mod corruption {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_capture_corruption_tests.rs"
    ));
}

impl Fixture {
    fn configure_native_capture_dpop(&mut self) -> TestResult {
        use chio_kernel::admission_operation::AdmissionDigest;
        use chio_kernel::dpop::authority::{
            DpopReplayAuthorityInputV1, DpopReplayAuthorityV1, DPOP_AUTHORITY_SCHEMA,
        };
        use chio_kernel::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
        use chio_kernel::dpop::{DpopNonceStore, DpopProof, DpopProofBody};
        let source = DpopNonceStore::new(16, std::time::Duration::from_secs(600));
        let store = self.authority.admission_operation_store();
        let fence = self.authority.mutation_fence();
        let authority_id = AdmissionIdentifier::try_new("authority", "native-capture-dpop")?;
        let snapshot = source.preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: authority_id.clone(),
            destination_authority_id: AdmissionIdentifier::try_new(
                "destination",
                &fence.store_uuid,
            )?,
        })?;
        let expected = store.expect_dpop_replay_source(
            &AdmissionIdentifier::try_new("instance", snapshot.instance_id())?,
            &authority_id,
            &source,
            &fence,
            now_ms()?,
        )?;
        store.import_dpop_replay_source(
            &authority_id,
            expected.expectation_id(),
            &source,
            &fence,
            now_ms()?,
        )?;
        let authority = DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
            destination_store_uuid: AdmissionIdentifier::try_new("destination", &fence.store_uuid)?,
            dpop_authority_id: authority_id,
            expectation_id: AdmissionDigest::try_new(
                "expectation",
                expected.expectation_id().as_str(),
            )?,
            proof_ttl_secs: 600,
            max_clock_skew_secs: 30,
        })?;
        store.activate_dpop_replay_source(&authority, &source, &fence, now_ms()?)?;
        self.kernel
            .set_operation_owned_dpop_authority(authority.clone())?;
        self.request.dpop_proof = Some(DpopProof::sign(
            DpopProofBody {
                schema: DPOP_AUTHORITY_SCHEMA.into(),
                replay_authority: Some(authority),
                capability_id: self.request.capability.id.clone(),
                tool_server: self.request.server_id.clone(),
                tool_name: self.request.tool_name.clone(),
                action_hash: chio_core::sha256_hex(&chio_core::canonical::canonical_json_bytes(
                    &self.request.arguments,
                )?),
                nonce: "native-capture-original-proof".into(),
                issued_at: now_ms()? / 1000,
                agent_key: self.agent.public_key(),
            },
            &self.agent,
        )?);
        Ok(())
    }
}

#[test]
fn native_atomic_capture_preserves_dpop_required_by_another_matching_grant() -> TestResult {
    let mut fixture = Fixture::new_with_seed_and_dpop(
        std::array::from_fn(|_| InformationLabel::bottom()),
        |_| Ok(None),
        true,
    )?;
    fixture.configure_native_capture_dpop()?;
    assert_eq!(
        fixture.request.capability.scope.grants[0].dpop_required,
        None
    );
    assert_eq!(
        fixture.request.capability.scope.grants[1].dpop_required,
        Some(true)
    );
    run_capture(&mut fixture, false)?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("captured original")?;
    assert!(original.matching_grants_require_dpop());
    assert!(operation.dpop_replay_ledger_digest().is_some());
    let (_, claims) = store
        .load_dpop_replay_claim_history(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("DPoP claims")?;
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].intent.grant_index(), 0);
    assert_eq!(claims[0].disposition, chio_kernel::admission_operation::dpop_claim::DpopReplayClaimDisposition::RetainedAfterDispatchCommit);
    Ok(())
}

#[test]
fn native_atomic_capture_retains_quota_and_ledger_without_tool_effect() -> TestResult {
    for egress in [false, true] {
        let mut fixture = super::super::public_fixture()?;
        let ledger = run_capture(&mut fixture, egress)?;
        assert_eq!(
            fixture.reopen_dispatch_ledger(&ledger.operation_id, |_| Ok(()))?,
            ledger
        );
    }
    Ok(())
}

fn run_capture(
    fixture: &mut Fixture,
    egress: bool,
) -> TestResult<chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1> {
    run_capture_through(fixture, egress, |fixture| {
        Ok(fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?)
    })
}

fn run_capture_through(
    fixture: &mut Fixture,
    egress: bool,
    invoke: impl FnOnce(&Fixture) -> TestResult<chio_kernel::ToolCallResponse>,
) -> TestResult<chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1> {
    run_capture_through_with_clearance(fixture, egress, InformationLabel::bottom(), invoke)
}

fn run_capture_through_with_clearance(
    fixture: &mut Fixture,
    egress: bool,
    clearance: InformationLabel,
    invoke: impl FnOnce(&Fixture) -> TestResult<chio_kernel::ToolCallResponse>,
) -> TestResult<chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1> {
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        super::super::registry(egress, clearance)?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(resolver.clone());
    let result = Arc::new(Mutex::new(None));
    fixture
        .kernel
        .install_native_capture_checkpoint_hook(Arc::new({
            let result = result.clone();
            move |authority| {
                let prepared = resolver
                    .prepare_dispatch(authority.prepare_egress()?)
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
                let (custody, capture) = prepared
                    .capture_invocation(authority)
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
                assert_eq!(
                    capture.operation.state(),
                    AdmissionOperationState::DispatchCommitted
                );
                let ledger = custody
                    .dispatch_ledger()
                    .ok_or_else(|| KernelError::Internal("capture ledger absent".into()))?;
                assert_eq!(
                    capture.operation.native_dispatch_ledger_digest(),
                    Some(&ledger.record_digest)
                );
                assert!(authority.prepare_egress().is_err());
                *result
                    .lock()
                    .map_err(|_| KernelError::Internal("capture result poisoned".into()))? =
                    Some((custody, capture));
                Ok(())
            }
        }));
    let response = invoke(fixture)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    let (custody, capture) = result
        .lock()
        .map_err(|_| "capture result poisoned")?
        .take()
        .ok_or_else(|| {
            format!(
                "capture did not succeed (egress={egress}): {:?}",
                response.reason
            )
        })?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.hook.legacy_dispatch.load(Ordering::SeqCst), 0);
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("captured quota absent")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 1)
    );
    let ledger = custody.dispatch_ledger().ok_or("capture ledger")?.clone();
    assert_eq!(
        capture.operation.native_dispatch_ledger_digest(),
        Some(&ledger.record_digest)
    );
    Ok(ledger)
}

#[test]
fn native_atomic_capture_faults_roll_back_budget_and_operation_together() -> TestResult {
    use chio_store_sqlite::admission_operation_store::NativeDispatchCaptureTestFault as Fault;
    for egress in [false, true] {
        for fault in [Fault::AfterBudgetCapture, Fault::AfterOperationCapture] {
            let mut fixture = super::super::public_fixture()?;
            let resolver = Arc::new(NativeFlowResolver::new(
                fixture.binding.clone(),
                super::super::registry(egress, InformationLabel::bottom())?,
                Arc::new(CountingEmptyClassifier::new()),
                Arc::new(Clock::default()),
                flow_config(),
            )?);
            fixture
                .kernel
                .set_security_pre_dispatch_hook(resolver.clone());
            fixture
                .authority
                .admission_operation_store()
                .inject_native_dispatch_capture_failure_for_test(fault)?;
            fixture
                .kernel
                .install_native_capture_checkpoint_hook(Arc::new(move |authority| {
                    resolver
                        .prepare_dispatch(authority.prepare_egress()?)
                        .and_then(|prepared| prepared.capture_invocation(authority))
                        .map(|_| ())
                        .map_err(|error| KernelError::GuardDenied(error.to_string()))
                }));
            let response = fixture
                .kernel
                .evaluate_tool_call_blocking_with_security_context(
                    &fixture.request,
                    &fixture.context,
                )?;
            fixture
                .authority
                .admission_operation_store()
                .clear_native_dispatch_capture_failure_for_test()?;
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("injected native capture failure")),
                "{fault:?}: {:?}",
                response.reason
            );
            assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
            let store = fixture.authority.admission_operation_store();
            let fence = fixture.authority.mutation_fence();
            let (operation, _) = store
                .load_unambiguous_retained_tool_request(
                    &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
                    &fence,
                    now_ms()?,
                )?
                .ok_or("retained failed capture")?;
            assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
            assert!(operation.dispatch_commit().is_none());
            assert!(operation.native_dispatch_ledger_digest().is_none());
            let usage = fixture
                .authority
                .budget_store()
                .get_invocation_quota_usage(&BudgetQuotaKey::grant(
                    &fixture.request.capability.id,
                    0,
                ))?
                .ok_or("held quota")?;
            assert_eq!(
                (usage.reserved_invocations, usage.captured_invocations),
                (1, 0)
            );
            let ledger = store
                .load_native_dispatch_ledger(operation.binding().operation_id(), &fence, now_ms()?)?
                .ok_or("preparation survived rollback")?;
            let value: serde_json::Value = serde_json::from_slice(&ledger.canonical_record)?;
            assert_eq!(value["egress_commitment"].is_null(), !egress);
            drop(store);
            assert_eq!(
                fixture.reopen_dispatch_ledger(&ledger.operation_id, |_| Ok(()))?,
                ledger
            );
        }
    }
    Ok(())
}
