// A native policy refusal needs a fixed signed owner and exact operation binding.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionReceiptMetadataV1, AdmissionTerminalReplay, ADMISSION_RECEIPT_METADATA_KEY,
};

fn missing_grant_refusal() -> TestResult<(
    Fixture,
    chio_kernel::ToolCallResponse,
    chio_kernel::admission_operation::AdmissionOperationV1,
)> {
    // This uses the legacy disclosure-grant family, whose valid lifetime is
    // 300 seconds. Recovery V2's distinct 60-second bound is not bypassed.
    let (mut fixture, _) = profile(false, 300)?;
    fixture.request.declassification_grant = None;
    fixture.request.execution_nonce = None;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        response.receipt.kernel_key,
        fixture.kernel.receipt_signing_public_key()
    );
    assert_eq!(
        response.receipt.capability_id,
        fixture.request.capability.id
    );
    assert_eq!(response.receipt.tool_server, fixture.request.server_id);
    assert_eq!(response.receipt.tool_name, fixture.request.tool_name);
    let (operation, retained) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("native missing-grant original custody absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(matches!(
        operation.terminal_replay(),
        Some(AdmissionTerminalReplay::Incident { .. })
    ));
    retained.validate_request_material(&fixture.request)?;
    retained.validate_native_security_context(&fixture.context)?;
    retained.validate_native_security_authority(&fixture.binding)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("missing-grant quota custody absent")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 0)
    );
    Ok((fixture, response, operation))
}

#[test]
fn missing_disclosure_grant_attests_native_policy_before_dispatch() -> TestResult {
    let (_, response, _) = missing_grant_refusal()?;
    assert!(
        response.receipt.evidence.iter().any(|guard| {
            guard.guard_name == "native-flow-resolver"
                && !guard.verdict
                && guard.details.as_deref() == Some("policy_flow_violation")
        }),
        "native policy refusal lacks a fixed signed owner witness"
    );
    Ok(())
}

#[test]
fn compensated_public_denial_is_bound_to_the_actual_native_operation() -> TestResult {
    let (_, response, operation) = missing_grant_refusal()?;
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|fields| fields.get(ADMISSION_RECEIPT_METADATA_KEY))
        .ok_or("signed public compensation denial lacks exact native admission metadata")?;
    let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(metadata.clone())?;
    assert_eq!(metadata.operation_id, *operation.binding().operation_id());
    assert_eq!(metadata.request_id, *operation.binding().request_id());
    assert_eq!(
        metadata.request_namespace_digest,
        *operation.binding().request_namespace_digest()
    );
    assert_eq!(
        metadata.request_binding_hash,
        *operation.binding().request_binding_hash()
    );
    assert_eq!(metadata.projected_operation_version, operation.version());
    assert_eq!(metadata.projected_state, operation.state());
    assert_eq!(
        metadata.projected_dispatch_state,
        operation.dispatch_state()
    );
    assert!(metadata.retained_dispatch_commit.is_none());
    assert_eq!(
        metadata.compensation_status,
        chio_kernel::admission_operation::AdmissionCompensationStatus::CompensatedBeforeDispatch
    );
    assert!(metadata.tool_outcome_id.is_none());
    assert!(metadata.tool_outcome_version.is_none());
    Ok(())
}

#[test]
fn arbitrary_capture_failure_or_panic_cannot_claim_native_policy_witness() -> TestResult {
    for panic in [false, true] {
        let (mut fixture, _) = profile(false, 300)?;
        fixture
            .kernel
            .install_native_capture_checkpoint_hook(Arc::new(move |_| {
                if panic {
                    panic!("policy_flow_violation");
                }
                Err(KernelError::GuardDenied("policy_flow_violation".into()))
            }));
        let response = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
        assert!(response.receipt.verify_signature()?);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        let (operation, _) = fixture
            .authority
            .admission_operation_store()
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &fixture.request.request_id)?,
                &fixture.authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("arbitrary native callback custody absent")?;
        assert_eq!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        assert!(operation.dispatch_commit().is_none());
        assert!(
            !response
                .receipt
                .evidence
                .iter()
                .any(|guard| { guard.guard_name == "native-flow-resolver" && !guard.verdict }),
            "an extension-controlled diagnostic acquired native policy evidence"
        );
    }
    Ok(())
}

struct ReservedOwnerSpoofGuard;
impl chio_kernel::Guard for ReservedOwnerSpoofGuard {
    fn name(&self) -> &str {
        "extension-policy-witness-spoof"
    }

    fn evaluate(
        &self,
        _: &chio_kernel::GuardContext<'_>,
    ) -> Result<chio_kernel::GuardDecision, KernelError> {
        Ok(chio_kernel::GuardDecision::allow_with_evidence(vec![
            chio_core::receipt::metadata::GuardEvidence {
                guard_name: "native-flow-resolver".into(),
                verdict: false,
                details: Some("policy_flow_violation".into()),
            },
        ]))
    }
}

#[test]
fn registered_guard_cannot_spoof_the_reserved_native_policy_owner() -> TestResult {
    let (mut fixture, _) = profile(false, 300)?;
    fixture.kernel.add_guard(Box::new(ReservedOwnerSpoofGuard));
    fixture
        .kernel
        .install_native_capture_checkpoint_hook(Arc::new(|_| {
            Err(KernelError::GuardDenied("policy_flow_violation".into()))
        }));
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    assert!(response.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let (operation, retained) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("spoof guard original custody absent")?;
    retained.validate_request_material(&fixture.request)?;
    retained.validate_native_security_context(&fixture.context)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(
        !response
            .receipt
            .evidence
            .iter()
            .any(|guard| { guard.guard_name == "native-flow-resolver" && !guard.verdict }),
        "ordinary guard evidence acquired the reserved native owner"
    );
    Ok(())
}

#[test]
fn ordinary_hook_registration_invalidates_even_the_same_native_owner() -> TestResult {
    let (mut fixture, issuer) = profile(false, 300)?;
    let flow = Arc::new(resolver(&fixture, &issuer)?.with_captured_lifecycle());
    flow.install_captured_on_kernel(&mut fixture.kernel)?;
    // This is a real host re-registration, with identical name, native binding
    // and Arc. It still invalidates the earlier reserved installation token.
    fixture.kernel.set_security_pre_dispatch_hook(flow);
    fixture.request.declassification_grant = None;
    fixture.request.execution_nonce = None;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    assert!(response.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let (operation, retained) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("replaced native owner original custody absent")?;
    retained.validate_native_security_authority(&fixture.binding)?;
    retained.validate_native_security_context(&fixture.context)?;
    retained.validate_request_material(&fixture.request)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(
        !response
            .receipt
            .evidence
            .iter()
            .any(|guard| { guard.guard_name == "native-flow-resolver" && !guard.verdict }),
        "ordinary re-registration retained native policy witness authority"
    );
    Ok(())
}

#[test]
fn compensated_native_denial_timestamp_uses_confirmed_projection_time() -> TestResult {
    struct PausedClock {
        calls: AtomicUsize,
        before: std::sync::atomic::AtomicU64,
        after: std::sync::atomic::AtomicU64,
    }
    impl chio_security_kernel::SecurityClock for PausedClock {
        fn now_unix_ms(&self) -> chio_security_types::ports::PortResult<u64> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.before.store(now_ms()?, Ordering::SeqCst);
                // Scheduling delay only. No request, capability, authority,
                // native policy, receipt or terminal record is substituted.
                std::thread::sleep(std::time::Duration::from_millis(1_100));
                self.after.store(now_ms()?, Ordering::SeqCst);
            }
            now_ms()
        }
    }
    let (mut fixture, issuer) = profile(false, 300)?;
    let clock = Arc::new(PausedClock {
        calls: AtomicUsize::new(0),
        before: std::sync::atomic::AtomicU64::new(0),
        after: std::sync::atomic::AtomicU64::new(0),
    });
    let purpose = DeclassificationPurpose::new("approved-disclosure")?;
    let config = FlowResolverConfig::new(
        restricted_label(),
        flow_config().category_labels,
        BTreeMap::from([(
            RecordId::new("native-disclosure-authority")?,
            issuer.public_key(),
        )]),
        60_000,
    )?;
    let flow = Arc::new(
        NativeFlowResolver::new(
            fixture.binding.clone(),
            declassification_registry(&purpose),
            Arc::new(CountingEmptyClassifier::new()),
            clock.clone(),
            config,
        )?
        .with_captured_lifecycle(),
    );
    flow.install_captured_on_kernel(&mut fixture.kernel)?;
    fixture.request.declassification_grant = None;
    fixture.request.execution_nonce = None;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert!(clock.calls.load(Ordering::SeqCst) > 0);
    assert!(
        clock.after.load(Ordering::SeqCst) / 1_000 > clock.before.load(Ordering::SeqCst) / 1_000,
        "the real native policy delay did not cross a second"
    );
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        response.receipt.kernel_key,
        fixture.kernel.receipt_signing_public_key()
    );
    assert_eq!(
        response.receipt.capability_id,
        fixture.request.capability.id
    );
    assert!(response.receipt.evidence.iter().any(|guard| {
        guard.guard_name == "native-flow-resolver"
            && !guard.verdict
            && guard.details.as_deref() == Some("policy_flow_violation")
    }));
    let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .ok_or("delayed native compensation metadata absent")?,
    )?;
    let store = fixture.authority.admission_operation_store();
    let (operation, original) = store
        .load_retained_tool_request(
            &metadata.operation_id,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("delayed native compensation custody absent")?;
    original.validate_request_material(&fixture.request)?;
    original.validate_native_security_context(&fixture.context)?;
    original.validate_native_security_authority(&fixture.binding)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(matches!(
        operation.terminal_replay(),
        Some(AdmissionTerminalReplay::Incident { .. })
    ));
    assert_eq!(metadata.projected_operation_version, operation.version());
    let database = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let physical_time: i64 = database.query_row(
        "SELECT json_extract(projection_json,'$.context.trusted_time_unix_ms')
         FROM admission_operation_terminal_projections WHERE operation_id=?1",
        [metadata.operation_id.as_str()],
        |row| row.get(0),
    )?;
    let physical_time = u64::try_from(physical_time)?;
    assert_eq!(metadata.trusted_time_unix_ms, physical_time);
    assert!(physical_time >= clock.after.load(Ordering::SeqCst));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("delayed native quota custody absent")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 0)
    );
    assert_eq!(
        response.receipt.timestamp,
        physical_time / 1_000,
        "native compensated public denial uses an earlier evaluation timestamp"
    );
    Ok(())
}
