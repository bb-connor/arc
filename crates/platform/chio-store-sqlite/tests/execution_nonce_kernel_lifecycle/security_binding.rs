//! Trusted identity remains bound across physical owner takeover and nonce use.

use super::*;
use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};
use chio_kernel::{SecurityInvocationContext, SecurityInvocationContextV1};
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;

fn context(request: &ToolCallRequest, generation: u64) -> TestResult<SecurityInvocationContext> {
    Ok(SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            TenantId::new("retained-tenant")?,
            SessionId::new("retained-session")?,
            PrincipalId::new(request.agent_id.clone())?,
            IsolationEpochId::new("retained-epoch")?,
            LineageId::new(request.capability.id.clone())?,
            generation,
        ),
    ))
}

#[test]
fn sqlite_nonce_preflight_retains_security_identity_across_restart() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let mut request = fixture.request(&runtime, "security-nonce-restart")?;
    let original = context(&request, 1)?;
    let preflight = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &original)?;
    assert_preflight(&preflight)?;
    let before = assert_state(&fixture, &request, "prepared")?;
    let selector = AdmissionIdentifier::try_new("request_id", request.request_id.clone())?;
    let fence = runtime.authority.mutation_fence();
    let (_, retained) = runtime
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(&selector, &fence, now_ms()?)?
        .ok_or("retained request")?;
    let encoded: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    assert_eq!(encoded["schema"], "chio.retained-tool-admission-request.v4");
    assert!(retained.authority_profile().is_some());
    assert_eq!(
        encoded["security_binding"]["context"]["context_generation"],
        1
    );
    drop(runtime);

    let runtime = fixture.open()?;
    assert!(runtime.authority.mutation_fence().owner_epoch > fence.owner_epoch);
    let (_, reloaded) = runtime
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &selector,
            &runtime.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("reloaded request")?;
    assert_eq!(reloaded.canonical_bytes(), retained.canonical_bytes());
    request.execution_nonce = Some(*preflight.execution_nonce.ok_or("nonce")?);
    for changed in [None, Some(context(&request, 2)?)] {
        let denied = match changed {
            Some(context) => runtime
                .kernel
                .evaluate_tool_call_blocking_with_security_context(&request, &context)?,
            None => runtime.kernel.evaluate_tool_call_blocking(&request)?,
        };
        assert_eq!(denied.verdict, Verdict::Deny, "{denied:?}");
        assert!(denied.output.is_none());
        assert_eq!(assert_state(&fixture, &request, "prepared")?, before);
        assert_eq!(
            count_rows(&fixture, "admission_execution_nonce_reservations")?,
            0
        );
        assert_eq!(count_rows(&fixture, "budget_authorization_holds")?, 1);
        assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    }
    let advanced =
        SecurityInvocationContext::v1(original.as_v1().clone().with_flow_state_generation(9));
    let completed = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &advanced)?;
    assert_eq!(completed.verdict, Verdict::Allow, "{completed:?}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    drop(runtime);

    let runtime = fixture.open()?;
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &advanced)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{replay:?}");
    assert_eq!(replay.receipt.id, completed.receipt.id);
    assert_eq!(replay.output, completed.output);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn sqlite_ordinary_terminal_rejects_changed_security_identity_after_restart() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "ordinary-security-restart")?;
    let original = context(&request, 1)?;
    let completed = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &original)?;
    assert_eq!(completed.verdict, Verdict::Allow, "{completed:?}");
    let operation_id = assert_state(&fixture, &request, "completed")?;
    let epoch = runtime.authority.mutation_fence().owner_epoch;
    drop(runtime);

    let runtime = fixture.open()?;
    assert!(runtime.authority.mutation_fence().owner_epoch > epoch);
    let denied = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request, 2)?)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{denied:?}");
    assert!(denied.output.is_none());
    assert_eq!(assert_state(&fixture, &request, "completed")?, operation_id);
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &original)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{replay:?}");
    assert_eq!(replay.receipt.id, completed.receipt.id);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}
