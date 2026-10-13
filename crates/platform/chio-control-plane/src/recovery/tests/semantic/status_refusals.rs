//! Authored status restrictions cover current authority refusal as well as provider errors.
use super::*;

#[tokio::test]
async fn native_current_withheld_read_keeps_its_coherent_status_audience() -> TestResult {
    let f = native_fixture("read-weak-manifest")?;
    let (runtime, request, profile) = prepare(
        &f,
        "current-withheld-read",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let audience = &profile.package.body().operations.as_slice()[0]
        .withheld_status
        .as_ref()
        .ok_or("withheld read must author a status audience")?
        .audience;
    let before = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let before = before.snapshot().ok_or("current source absent")?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());
    let response = runtime
        .execute_step(&f.process, "root", "current-withheld-read", &request)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let after = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let after = after.snapshot().ok_or("current source absent")?;
    assert!(audience.flows_to(&after.principal_label));
    assert!(audience.flows_to(&after.lineage_label));
    assert!(audience.flows_to(&after.session_label));
    Ok(())
}

#[tokio::test]
async fn native_stale_acl_refusal_keeps_the_authored_withheld_status_audience() -> TestResult {
    let f = native_fixture("read-weak-manifest")?;
    let (runtime, request, profile) = prepare(
        &f,
        "stale-acl-status",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let audience = &profile.package.body().operations.as_slice()[0]
        .withheld_status
        .as_ref()
        .ok_or("withheld read must author a status audience")?
        .audience;
    let before = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let before = before.snapshot().ok_or("initial source absent")?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());

    let mut current = profile.invocation.audience.body().clone();
    current.provider_version = ProtectedText::new("\"resource-v2\"")?;
    let observed = now_ms()?.max(
        current
            .observed_at_unix_ms
            .get()
            .checked_add(1)
            .ok_or("ACL observation clock overflow")?,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while now_ms()? < observed {
        if std::time::Instant::now() >= deadline {
            return Err("authority clock did not advance".into());
        }
        tokio::task::yield_now().await;
    }
    current.observed_at_unix_ms = SafeInteger::new(observed)?;
    let current = SignedSemanticAudienceV1::sign(current, &profile.resolver)?;
    assert!(current.verify_signature()?);
    assert_ne!(current, profile.invocation.audience);
    f.authority
        .admission_operation_store()
        .install_semantic_audience(&current)?;
    assert!(now_ms()? < profile.invocation.action.valid_until_unix_ms.get());
    let result = runtime
        .execute_step(&f.process, "root", "stale-acl-status", &request)
        .await;
    assert!(
        result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "the stale exact ACL must refuse before provider submission"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert!(now_ms()? < profile.invocation.action.valid_until_unix_ms.get());
    let (operation, _) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("stale ACL refusal original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    let after = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let after = after.snapshot().ok_or("current source absent")?;
    assert!(
        audience.flows_to(&after.principal_label),
        "observable current authority refusal must retain its authored status floor"
    );
    assert!(audience.flows_to(&after.lineage_label));
    assert!(audience.flows_to(&after.session_label));
    Ok(())
}
