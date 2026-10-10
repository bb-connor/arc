//! Finish a custody fixture through actual hold reversal and terminal projection.
//! No generic dispatch transition or executable native permission is fabricated.
use super::*;
use chio_kernel::admission_operation::verified_released_pre_dispatch_compensation_projection_for_test;
use chio_kernel::budget_store::{BudgetQuotaKey, BudgetReverseHoldRequest};

pub(super) fn compensate(
    fixture: &Fixture,
    pending: &Pending,
) -> AnchoredTestResult<AdmissionOperationV1> {
    let operation = &pending.operation;
    let capability_id = operation.binding().capability_id().as_str();
    let hold_id = operation.budget_hold_id().ok_or("fixture hold")?.as_str();
    let authority = BudgetEventAuthority {
        authority_id: fixture.fence.store_uuid.clone(),
        lease_id: fixture.fence.lease_id.clone(),
        lease_epoch: fixture.fence.owner_epoch,
    };
    let budget = fixture.authority.budget_store();
    // The custody fixture already attached this identifier. Materialize its
    // physical reservation before exercising the terminal settlement boundary.
    assert!(matches!(
        budget.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: capability_id.into(),
            grant_index: 0,
            max_invocations: Some(1),
            invocation_quotas: vec![],
            cumulative_approval: None,
            admission_binding: Some(BudgetAdmissionBinding {
                operation_id: operation.binding().operation_id().as_str().into(),
                revocation_set: CanonicalRevocationSet::canonicalize(vec![capability_id.into()])?,
                authorization_artifact_digests: vec![operation
                    .to_persisted()
                    .binding
                    .authorization_capability_hash
                    .as_str()
                    .into()],
                last_observed_revocation: None,
                supplemental_verifier_id: None,
                supplemental_verifier_config_digest: None,
                supplemental_authorization_artifact_digest: None,
                supplemental_authorization_expires_at: None,
            }),
            requested_exposure_units: 0,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            hold_id: Some(hold_id.into()),
            event_id: Some(format!("{hold_id}-authorize")),
            authority: Some(authority.clone()),
        })?,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let projection = || -> AnchoredTestResult<_> {
        let lease = renew(fixture, operation, &pending.lease)?;
        Ok(
            verified_released_pre_dispatch_compensation_projection_for_test(
                operation,
                AdmissionProjectionContext {
                    operation_id: operation.binding().operation_id().clone(),
                    request_id: operation.binding().request_id().clone(),
                    expected_operation_version: operation.version(),
                    trusted_time_unix_ms: now_ms(),
                    coordinator_lease_id: lease.coordinator_lease_id().clone(),
                    coordinator_lease_epoch: lease.coordinator_lease_epoch(),
                    store_fence: fixture.fence.clone(),
                },
                serde_json::json!({"policy": "native-egress-compensation"}),
            )?,
        )
    };
    // Compensation must not rely on the test envelope's release claim alone.
    assert!(fixture
        .store
        .commit_terminal_projection(&projection()?)
        .is_err());
    let quota = budget
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(capability_id, 0))?
        .ok_or("reserved quota")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (1, 0)
    );
    budget.reverse_budget_hold(BudgetReverseHoldRequest {
        capability_id: capability_id.into(),
        grant_index: 0,
        reversed_exposure_units: 0,
        hold_id: Some(hold_id.into()),
        event_id: Some(format!("{hold_id}-reverse")),
        expected_cumulative_approval_state: None,
        authority: Some(authority),
    })?;
    let terminal = fixture.store.commit_terminal_projection(&projection()?)?;
    assert_eq!(
        terminal.state,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let quota = budget
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(capability_id, 0))?
        .ok_or("reversed quota")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (0, 0)
    );
    let operation = fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("compensated operation")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    Ok(operation)
}
