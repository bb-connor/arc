use super::*;
use crate::recovery::{recovery_explanation_router, RecoveryExplanationService};
use chio_core_types::recovery::SignedRecoveryExplanationViewV1;
fn service(f: &RecoveryFixture) -> TestResult<RecoveryExplanationService> {
    Ok(RecoveryExplanationService::new(
        f.runtime.scope().clone(),
        AuthorityDomainId::new("advisory-trust")?,
        IssuerId::new("advisory-issuer")?,
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[31; 32]))),
        ExplanationLimitsV1 {
            offers: SafeInteger::new(16)?,
            work: SafeInteger::new(4096)?,
        },
    )?)
}

#[tokio::test]
async fn recovery_top_preview_clearance_is_rejected_at_deployment() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let store = f.authority.admission_operation_store();
    let mut profile =
        store.deployment(f.runtime.scope(), &f.authority.mutation_fence(), now_ms()?)?;
    let mut actors = profile.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::Top;
    profile.actors = NonEmptyBoundedList::new(actors)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    assert!(store.configure_recovery_deployment(&profile).is_err());
    Ok(())
}

#[tokio::test]
async fn recovery_safe_view_permission_cannot_inspect_the_protected_graph() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let service = service(&f)?;
    let mut scope = f.control.scope.clone();
    scope
        .grants
        .retain(|grant| grant.tool_name != "explanation.inspect");
    let view_only = f.kernel.issue_capability(&f.control.subject, scope, 1200)?;
    assert!(f.runtime.explain(&view_only, &id, &service).is_ok());
    assert!(f
        .runtime
        .inspect_explanation(&view_only, &id, &service)
        .is_err());
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn recovery_native_facts_do_not_invent_workflow_source_versions() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let service = service(&f)?;
    let artifact = f.runtime.inspect_explanation(&f.control, &id, &service)?;
    for id in ["capability", "policy", "recipient", "coverage"] {
        let fact = artifact
            .snapshot
            .observations
            .as_slice()
            .iter()
            .find(|fact| fact.id.as_str() == id)
            .ok_or("missing native fact")?;
        let state = serde_json::to_value(&fact.state)?;
        assert!(
            state.get("version").is_none(),
            "{id} has no workflow-owned version"
        );
        assert_eq!(state["kind"], serde_json::json!("freshness_qualified"));
        assert!(fact.expires_at_unix_ms > fact.observed_at_unix_ms);
    }
    Ok(())
}

#[tokio::test]
async fn recovery_report_reference_resolves_the_original_graph_under_separate_live_authority(
) -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let service = service(&f)?;
    let view = f.runtime.explain(&f.control, &id, &service)?;
    let reference = &view.body().report_ref;
    let first = f
        .runtime
        .inspect_explanation_reference(&f.control, &id, reference, &service)?;
    let second = f
        .runtime
        .inspect_explanation_reference(&f.control, &id, reference, &service)?;
    assert!(
        Arc::ptr_eq(&first, &second),
        "inspection must not reobserve the basis"
    );
    assert_eq!(first.view.body(), view.body());
    assert_eq!(&first.report.body().protected_graph_ref, reference);
    assert!(first.report.verify_signature()?);
    assert!(first.view.verify_signature()?);
    assert_eq!(external_count(&f.path)?, 0);

    let mut scope = f.control.scope.clone();
    scope
        .grants
        .retain(|grant| grant.tool_name != "explanation.inspect");
    let view_only = f.kernel.issue_capability(&f.control.subject, scope, 1200)?;
    for (capability, workflow, reference) in [
        (&view_only, id.clone(), reference.clone()),
        (
            &f.control,
            WorkflowId::new("other-workflow")?,
            reference.clone(),
        ),
        (
            &f.control,
            id.clone(),
            ExplanationRef::new("advice:missing")?,
        ),
    ] {
        assert!(matches!(
            f.runtime
                .inspect_explanation_reference(capability, &workflow, &reference, &service),
            Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
        ));
    }
    f.kernel.revoke_capability(&f.control.id)?;
    assert!(matches!(
        f.runtime
            .inspect_explanation_reference(&f.control, &id, reference, &service),
        Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
    ));
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn recovery_graph_return_refuses_clock_rollback_after_live_authority_recheck() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let service = service(&f)?;
    let view = f.runtime.explain(&f.control, &id, &service)?;
    let issued = view.body().issued_at_unix_ms.get();
    let inside = issued.checked_add(1).ok_or("issued time overflow")?;
    let before_issue = issued.checked_sub(1).ok_or("issued time underflow")?;
    let expires = view.body().expires_at_unix_ms.get();
    assert!(inside < expires);
    let lookup = |first, last| {
        let mut samples = [first, last].into_iter();
        f.runtime.inspect_explanation_reference_with_test_time(
            &f.control,
            &id,
            &view.body().report_ref,
            &service,
            || {
                samples
                    .next()
                    .ok_or(crate::recovery::RecoveryRuntimeError::Unavailable)
            },
        )
    };
    let valid = lookup(inside, inside)?;
    assert_eq!(valid.view.body(), view.body());
    assert!(valid.report.verify_signature()?);
    assert!(matches!(
        lookup(before_issue, inside),
        Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
    ));
    assert!(matches!(
        lookup(inside, expires),
        Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
    ));
    assert!(
        matches!(
            lookup(inside, before_issue),
            Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
        ),
        "a rollback after live reauthentication cannot return a future-issued graph"
    );
    assert_eq!(external_count(&f.path)?, 0);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn recovery_live_report_recomputes_without_changing_workflow_budget_or_effect() -> TestResult
{
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let service = service(&f)?;
    let before = chio_core::canonical_json_bytes(&f.record(&id)?)?;
    let calls = f.process.process("root")?.tree_calls;
    let artifact = f.runtime.inspect_explanation(&f.control, &id, &service)?;
    assert_eq!(
        artifact.view.body().projection.candidates.as_slice()[0].assessment,
        ExplanationAssessmentV1::FeasibleUnderSnapshot
    );
    assert!(artifact.report.verify_signature()?);
    assert!(artifact.view.verify_signature()?);
    let report = artifact.report.body();
    let clearance = artifact.snapshot.context_label.clone();
    let key = service.public_key();
    chio_recovery::verify_explanation_report(
        &artifact.report,
        &chio_recovery::ExplanationReportInputs {
            snapshot: &artifact.snapshot,
            registry: &artifact.registry,
            view: artifact.view.body(),
            audience: chio_recovery::ExplanationAudience {
                recipient: &report.recipient,
                clearance: &clearance,
                validity_ceiling_unix_ms: SafeInteger::new(f.control.expires_at * 1000)?,
            },
        },
        &chio_recovery::ExplanationExpectedTrust {
            key: &key,
            trust_domain: &report.trust_domain,
            issuer: &report.issuer,
            scope: f.runtime.scope(),
            deployment_digest: artifact.snapshot.deployment_digest,
            policy_digest: artifact.snapshot.policy_digest,
            contract_digest: artifact.snapshot.contract_digest,
            intent_digest: artifact.snapshot.intent_digest,
            limits: report.limits,
        },
        SafeInteger::new(now_ms()?)?,
    )?;
    assert_eq!(before, chio_core::canonical_json_bytes(&f.record(&id)?)?);
    assert_eq!(calls, f.process.process("root")?.tree_calls);
    assert_eq!(external_count(&f.path)?, 0);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert!(!format!("{artifact:?}").contains("private-canary"));
    Ok(())
}
#[tokio::test]
async fn recovery_equal_label_foreign_generation_invalidates_live_resume() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let first = f.process.tool_request(
        "root",
        "initial-basis",
        "server-a",
        "send",
        f.seed.arguments.clone(),
    )?;
    f.process
        .invoke_known_only("root", "initial-basis", &first)
        .await?;
    let id = f.ready().await?;
    let service = service(&f)?;
    let artifact = f.runtime.inspect_explanation(&f.control, &id, &service)?;
    assert_eq!(
        artifact.view.body().projection.candidates.as_slice()[0].assessment,
        ExplanationAssessmentV1::FeasibleUnderSnapshot
    );
    let retained = artifact.snapshot.intent_digest;
    let foreign = f.process.tool_request(
        "root",
        "foreign-basis",
        "server-a",
        "send",
        f.seed.arguments.clone(),
    )?;
    f.process
        .invoke_known_only("root", "foreign-basis", &foreign)
        .await?;
    let fresh = f.runtime.inspect_explanation(&f.control, &id, &service)?;
    assert_eq!(
        fresh.view.body().projection.candidates.as_slice()[0].assessment,
        ExplanationAssessmentV1::NeedsFreshEvidence
    );
    assert_eq!(fresh.snapshot.intent_digest, retained);
    let revision = f.record(&id)?.revision;
    assert!(f
        .execute(
            "stale-explanation-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: revision
            }
        )
        .await
        .is_err());
    assert!(!f.record(&id)?.captured);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}
#[tokio::test]
async fn recovery_policy_and_recipient_changes_cannot_authorize_with_old_advice() -> TestResult {
    for change in 0..2 {
        let f = RecoveryFixture::new(false)?;
        let id = f.ready().await?;
        let service = service(&f)?;
        let artifact = f.runtime.inspect_explanation(&f.control, &id, &service)?;
        assert!(artifact.report.verify_signature()?);
        let revision = f.record(&id)?.revision;
        let store = f.authority.admission_operation_store();
        let mut profile =
            store.deployment(f.runtime.scope(), &f.authority.mutation_fence(), now_ms()?)?;
        if change == 0 {
            profile.policy_digest = PolicyDigest::from_bytes([91; 32]);
        } else {
            profile.recipient = DestinationId::new("different-provider-audience")?;
            profile.server_id =
                chio_security_types::ports::RecordId::new("different-provider-audience")?;
        }
        profile.authority_scope = recovery_authority_scope_digest(&profile)?;
        store.configure_recovery_deployment(&profile)?;
        assert!(f.runtime.explain(&f.control, &id, &service).is_err());
        assert!(f
            .execute(
                "stale-policy-recipient",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: id.clone(),
                    expected_revision: revision
                }
            )
            .await
            .is_err());
        assert_eq!(external_count(&f.path)?, 0);
        assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
#[tokio::test]
async fn recovery_original_revocation_is_observed_and_control_revocation_refuses_advice(
) -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let service = service(&f)?;
    f.kernel.revoke_capability(&f.seed.capability.id)?;
    let view = f.runtime.explain(&f.control, &id, &service)?;
    assert_eq!(
        view.body().projection.candidates.as_slice()[0].assessment,
        ExplanationAssessmentV1::BlockedByCapability
    );
    f.kernel.revoke_capability(&f.control.id)?;
    assert!(f.runtime.explain(&f.control, &id, &service).is_err());
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}
#[tokio::test]
async fn recovery_signer_roles_and_live_transport_reject_report_as_authority() -> TestResult {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let forbidden = RecoveryExplanationService::new(
        f.runtime.scope().clone(),
        AuthorityDomainId::new("advisory-trust")?,
        IssuerId::new("issuer")?,
        f.runtime.signer.clone(),
        ExplanationLimitsV1 {
            offers: SafeInteger::new(16)?,
            work: SafeInteger::new(4096)?,
        },
    )?;
    assert!(f.runtime.explain(&f.control, &id, &forbidden).is_err());
    let service = Arc::new(service(&f)?);
    let router = recovery_explanation_router(f.runtime.clone(), service.clone());
    let envelope = serde_json::json!({"capability":String::from_utf8(chio_core::canonical_json_bytes(&f.control)?)?,"workflow_id":id});
    let request = || -> TestResult<Request<Body>> {
        Ok(Request::builder()
            .method("POST")
            .uri("/v1/recovery/explain")
            .header("content-type", "application/json")
            .body(Body::from(chio_core::canonical_json_bytes(&envelope)?))?)
    };
    let response = router.clone().oneshot(request()?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 262144).await?;
    let view: SignedRecoveryExplanationViewV1 = chio_core_types::recovery::decode_contract(&bytes)?;
    assert!(view.verify_signature()?);
    assert!(f.runtime.execute(&f.control, &bytes).await.is_err());
    let mut injection = envelope.clone();
    injection["report"] = serde_json::from_slice(&bytes)?;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/recovery/explain")
                .body(Body::from(chio_core::canonical_json_bytes(&injection)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    f.kernel.revoke_capability(&f.control.id)?;
    assert_eq!(
        router.oneshot(request()?).await?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(external_count(&f.path)?, 0);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[tokio::test]
async fn recovery_cancelled_control_never_looks_feasible_and_advice_never_renews_it() -> TestResult
{
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let service = service(&f)?;
    let before = f.record(&id)?;
    f.execute(
        "cancel-before-explanation",
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: id.clone(),
            expected_revision: before.revision,
        },
    )
    .await?;
    let view = f.runtime.explain(&f.control, &id, &service)?;
    assert_eq!(
        view.body().projection.candidates.as_slice()[0].assessment,
        ExplanationAssessmentV1::NoRegisteredRemedy
    );
    assert_eq!(external_count(&f.path)?, 0);
    assert!(!f.record(&id)?.captured);
    Ok(())
}

#[tokio::test]
async fn recovery_limited_native_audience_refuses_without_exposing_private_basis() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let key = Keypair::from_seed(&[46; 32]);
    let capability = f.kernel.issue_capability(
        &key.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "chio.recovery".into(),
                tool_name: "inspect".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        },
        1200,
    )?;
    let mut profile = f.kernel.recovery_deployment(f.runtime.scope())?;
    let mut actors = profile.actors.as_slice().to_vec();
    actors.push(RecoveryActorAssignment {
        subject: key.public_key(),
        principal: PrincipalId::new("limited-viewer")?,
        permissions: BoundedList::new(vec![RecoveryPermission::Inspect])?,
        preview_clearance: InformationLabel::bottom(),
    });
    profile.actors = NonEmptyBoundedList::new(actors)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&profile)?;
    let id = f.ready().await?;
    let service = service(&f)?;
    assert!(f.runtime.explain(&capability, &id, &service).is_err());
    assert!(f
        .runtime
        .inspect_explanation(&capability, &id, &service)
        .is_err());
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let router = recovery_explanation_router(f.runtime.clone(), Arc::new(service));
    let wire = serde_json::json!({"capability":String::from_utf8(chio_core::canonical_json_bytes(&capability)?)?, "workflow_id":id});
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/recovery/explain")
                .body(Body::from(chio_core::canonical_json_bytes(&wire)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        to_bytes(response.into_body(), 262144).await?.as_ref(),
        b"recovery.authority_denied"
    );
    assert_eq!(external_count(&f.path)?, 0);
    assert!(!f.record(&id)?.captured);
    Ok(())
}

#[tokio::test]
async fn recovery_modeled_historical_top_preview_remains_data_and_cannot_disclose_advice(
) -> TestResult {
    use chio_store_sqlite::admission_operation_store::retain_recovery_fixture_legacy_top_actor;

    let f = RecoveryFixture::new(false)?;
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    let mut finite = store.deployment(f.runtime.scope(), &fence, now_ms()?)?;
    let mut actors = finite.actors.as_slice().to_vec();
    let principal = actors[0].principal.clone();
    let mut permissions = actors[0].permissions.as_slice().to_vec();
    if !permissions.contains(&RecoveryPermission::KnowledgeRead) {
        permissions.push(RecoveryPermission::KnowledgeRead);
    }
    permissions.sort();
    actors[0].permissions = BoundedList::new(permissions)?;
    finite.actors = NonEmptyBoundedList::new(actors)?;
    finite.authority_scope = recovery_authority_scope_digest(&finite)?;
    store.configure_recovery_deployment(&finite)?;

    let id = f.ready().await?;
    let service = service(&f)?;
    let original = f.runtime.inspect_explanation(&f.control, &id, &service)?;
    let reference = original.view.body().report_ref.clone();
    assert!(original.report.verify_signature()?);
    assert!(original.view.verify_signature()?);
    assert!(f.runtime.explain(&f.control, &id, &service).is_ok());
    assert_eq!(external_count(&f.path)?, 0);
    let capability_bytes = chio_core::canonical_json_bytes(&f.control)?;

    // This default-off protected writer models predecessor-accepted data.
    // It does not represent an execution by a genuinely old binary.
    let retained =
        retain_recovery_fixture_legacy_top_actor(&store, &fence, f.runtime.scope(), &principal)?;
    assert_eq!(
        retained.actors.as_slice()[0].preview_clearance,
        InformationLabel::Top
    );
    assert_eq!(
        recovery_authority_scope_digest(&retained)?,
        retained.authority_scope
    );
    let decoded = f.kernel.recovery_deployment(f.runtime.scope())?;
    assert_eq!(
        chio_core::canonical_json_bytes(&decoded)?,
        chio_core::canonical_json_bytes(&retained)?,
        "historical Top remains structurally authenticated data"
    );
    assert_eq!(decoded.native_authority, finite.native_authority);
    assert_eq!(decoded.policy_digest, finite.policy_digest);
    assert_eq!(decoded.contract_digest, finite.contract_digest);
    assert_eq!(
        decoded.actors.as_slice()[0].permissions,
        finite.actors.as_slice()[0].permissions
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&f.control)?,
        capability_bytes
    );

    for permission in [
        RecoveryPermission::Inspect,
        RecoveryPermission::InspectExplanationGraph,
    ] {
        let actor =
            f.kernel
                .authenticate_recovery_actor(f.runtime.scope(), &f.control, permission)?;
        assert_eq!(actor.principal(), &principal);
        assert_eq!(actor.permission(), permission);
    }

    assert!(matches!(
        f.runtime.explain(&f.control, &id, &service),
        Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
    ));
    assert!(matches!(
        f.runtime.inspect_explanation(&f.control, &id, &service),
        Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
    ));
    assert!(matches!(
        f.runtime
            .inspect_explanation_reference(&f.control, &id, &reference, &service),
        Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
    ));
    assert_eq!(external_count(&f.path)?, 0);

    store.configure_recovery_deployment(&finite)?;
    let restored = f
        .runtime
        .inspect_explanation_reference(&f.control, &id, &reference, &service)?;
    assert_eq!(restored.report.body(), original.report.body());
    assert_eq!(restored.view.body(), original.view.body());
    assert!(restored.report.verify_signature()?);
    assert!(restored.view.verify_signature()?);
    assert!(f.runtime.explain(&f.control, &id, &service).is_ok());
    assert_eq!(external_count(&f.path)?, 0);
    assert_eq!(
        chio_core::canonical_json_bytes(&f.control)?,
        capability_bytes
    );
    Ok(())
}
