use super::*;

#[test]
fn durable_admission_passes_opaque_supplemental_bytes_to_installed_verifier() {
    struct BoundVerifier;

    impl crate::supplemental_quota::SupplementalQuotaVerifier for BoundVerifier {
        fn verify(
            &self,
            signed_extension: &[u8],
            context: &crate::supplemental_quota::SupplementalQuotaVerificationContext,
        ) -> Result<
            crate::supplemental_quota::SupplementalQuotaVerificationRecord,
            crate::supplemental_quota::SupplementalQuotaVerifierError,
        > {
            let request_binding_hash =
                crate::supplemental_quota::supplemental_request_binding_hash(context).map_err(
                    |error| {
                        crate::supplemental_quota::SupplementalQuotaVerifierError::new(
                            error.to_string(),
                        )
                    },
                )?;
            Ok(
                crate::supplemental_quota::SupplementalQuotaVerificationRecord {
                    profile: crate::supplemental_quota::BROKER_CAPABILITY_EXECUTION_PROFILE
                        .to_string(),
                    broker_capability_id: "broker-capability-7".to_string(),
                    issuer: context.subject.clone(),
                    request_constraint_digest: "a".repeat(64),
                    max_invocations: 7,
                    authorization_artifact_digest:
                        crate::supplemental_quota::supplemental_authorization_artifact_digest(
                            signed_extension,
                        ),
                    supplemental_revocation_ids: vec!["broker-capability-7".to_string()],
                    expires_at: current_unix_timestamp() + 300,
                    request_binding_hash,
                    capability_id: context.capability_id.clone(),
                    capability_digest: context.capability_digest.clone(),
                    request_namespace_digest: context.request_namespace_digest.clone(),
                    operation_id: context.operation_id.clone(),
                    subject: context.subject.clone(),
                    request_id: context.request_id.clone(),
                    normalized_destination: context.normalized_destination.clone(),
                    arguments_hash: context.arguments_hash.clone(),
                    negotiated_features: context.negotiated_features.clone(),
                },
            )
        }
    }

    let (mut kernel, mut request, _store, _invocations) =
        durable_admission_fixture("durable-supplemental-verifier");
    kernel
        .set_supplemental_quota_verifier(
            std::sync::Arc::new(BoundVerifier),
            crate::supplemental_quota::SupplementalQuotaVerifierBinding {
                verifier_identity: "test/bound-verifier.v1".to_string(),
                configuration_digest: "b".repeat(64),
            },
        )
        .expect("valid verifier binding");
    request.supplemental_authorization = Some(
        chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
            signed_extension: "opaque-signed-extension".to_string(),
        },
    );
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");

    let admission = kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        .expect("verified durable admission")
        .expect("covered durable admission");

    let verified = admission
        .supplemental_quota()
        .expect("verified supplemental quota");
    assert_eq!(verified.max_invocations(), 7);
    assert_eq!(verified.broker_capability_id(), "broker-capability-7");
    assert_eq!(
        admission
            .operation()
            .supplemental_authorization_digest()
            .map(crate::admission_operation::AdmissionDigest::as_str),
        Some(verified.authorization_artifact_digest())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_durable_guard_evaluation_terminalizes_before_dispatch() {
    struct ParkingGuard {
        started: std::sync::Arc<tokio::sync::Notify>,
    }

    impl Guard for ParkingGuard {
        fn name(&self) -> &str {
            "durable-parking-guard"
        }

        fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            self.started.notify_one();
            std::thread::sleep(std::time::Duration::from_secs(2));
            Ok(GuardDecision::allow())
        }
    }

    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-dropped-guard-evaluation");
    kernel.config.deadlines.always_offload_guards = true;
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    kernel.add_guard(Box::new(ParkingGuard {
        started: started.clone(),
    }));
    let kernel = std::sync::Arc::new(kernel);
    let evaluation = {
        let kernel = kernel.clone();
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .expect("guard evaluation started");
    evaluation.abort();
    assert!(evaluation.await.is_err());

    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn startup_recovery_terminalizes_admission_before_budget_authorization() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-startup-before-budget");
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");
    let admission = kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        .expect("begin durable admission")
        .expect("covered durable admission");
    assert_eq!(
        admission.state(),
        AdmissionOperationState::BrokerAttemptRegistered
    );
    drop(admission);

    assert_eq!(
        kernel
            .reconcile_recoverable_admissions()
            .expect("recover pre-budget admission"),
        1
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn startup_recovery_reverses_the_executable_hold_after_budget_authorization() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-startup-after-budget");
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");
    let now_unix_ms = current_unix_timestamp_ms();
    let mut admission = kernel
        .begin_durable_tool_admission(&request, &matching, now_unix_ms)
        .expect("begin durable admission")
        .expect("covered durable admission");
    let outcome = kernel
        .check_and_increment_budget(
            &request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now_unix_ms,
        )
        .expect("executable hold authorization");
    assert!(matches!(outcome, BudgetAdmissionOutcome::Authorized { .. }));
    assert_eq!(admission.state(), AdmissionOperationState::BudgetAuthorized);
    let hold_id = admission.budget_hold_id(0);
    let open = store
        .budget_store()
        .get_budget_hold(&hold_id)
        .expect("hold snapshot")
        .expect("authorized hold");
    assert!(open.disposition.is_open());

    // The coordinator dies here. Recovery must reverse the retained hold before
    // it can project a no-effect compensation, and must never dispatch.
    drop(admission);
    assert_eq!(
        kernel
            .reconcile_recoverable_admissions()
            .expect("recover authorized admission"),
        1
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let reversed = store
        .budget_store()
        .get_budget_hold(&hold_id)
        .expect("hold snapshot")
        .expect("retained hold");
    assert_eq!(
        reversed.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reversed
    );
    assert_eq!(reversed.remaining_exposure_units, 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        kernel
            .reconcile_recoverable_admissions()
            .expect("idempotent recovery"),
        0
    );
}

#[test]
fn durable_pre_dispatch_denial_commits_terminal_compensation() {
    struct DenyAll;

    impl Guard for DenyAll {
        fn name(&self) -> &str {
            "durable-deny-all"
        }

        fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }

    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-pre-dispatch-denial");
    kernel.add_guard(Box::new(DenyAll));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("terminal pre-dispatch denial");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("terminal compensation replay");
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}
