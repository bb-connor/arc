//! Withholding requires a declared status audience before any native effect.
use super::*;

fn prepare_missing_status(
    fixture: &RecoveryFixture,
    key: &str,
) -> TestResult<(NativeSemanticRuntime, ToolCallRequest, SemanticFixture)> {
    let (runtime, mut request, mut profile) =
        prepare(fixture, key, SemanticOutputDispositionV1::ReturnValue)?;
    assert!(profile.package.body().operations.as_slice()[0]
        .withheld_status
        .is_none());
    assert!(profile.invocation.annotations.as_slice().is_empty());
    assert!(profile.invocation.endorsements.as_slice().is_empty());
    let mut step = profile.plan.steps.as_slice()[0].clone();
    step.output = SemanticOutputDispositionV1::Withhold;
    profile.plan.steps = NonEmptyBoundedList::new(vec![step])?;
    profile.invocation.action.plan = runtime.accept_plan(&fixture.control, &profile.plan)?;
    profile.invocation.action.output = SemanticOutputDispositionV1::Withhold;
    request.arguments = serde_json::to_value(&profile.invocation)?;
    Ok((runtime, request, profile))
}

#[tokio::test]
async fn native_missing_status_refuses_before_effect() -> TestResult {
    let fixture = native_fixture("read-missing-status")?;
    let key = "current-missing-status";
    let (runtime, request, _) = prepare_missing_status(&fixture, key)?;
    let result = runtime
        .execute_step(&fixture.process, "root", key, &request)
        .await;
    assert!(
        result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "fresh missing status declaration must refuse before dispatch"
    );
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    let (operation, _) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("current missing status original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    Ok(())
}
