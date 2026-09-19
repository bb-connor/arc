use super::*;
use chio_core::capability::scope::MonetaryAmount;
use chio_kernel::budget_store::{
    BudgetAuthorizeCumulativeApprovalRequest, BudgetCumulativeApprovalAccountKey,
    BudgetCumulativeApprovalRequest, BudgetInvocationQuota, BudgetQuotaKey, BudgetQuotaProfile,
};

#[test]
fn durable_nonce_preflight_restores_composite_budgets_but_cleanup_does_not_grant_approval(
) -> TestResult {
    for approved in [false, true] {
        let mut fixture = unowned_prepared_nonce_fixture(Some(60))?;
        let mut request = request(&fixture)?;
        request.requested_exposure_units = 5;
        request.max_cost_per_invocation = Some(5);
        request.max_total_cost_units = Some(5);
        request.invocation_quotas = vec![
            BudgetInvocationQuota {
                key: BudgetQuotaKey::grant(&request.capability_id, 0),
                max_invocations: 1,
            },
            BudgetInvocationQuota {
                key: BudgetQuotaKey {
                    profile: BudgetQuotaProfile::AggregateCapabilityInvocation,
                    owner_id: request.capability_id.clone(),
                    grant_index: None,
                },
                max_invocations: 1,
            },
        ];
        let account = BudgetCumulativeApprovalAccountKey {
            authority_id: "approval-authority".into(),
            owner_id: "approval-owner".into(),
            approval_budget_id: "approval-budget".into(),
            approval_budget_epoch: 1,
            root_grant_hash: "a".repeat(64),
            delegation_root_id: None,
            root_binding_digest: None,
            currency: "USD".into(),
        };
        request.cumulative_approval = Some(BudgetCumulativeApprovalRequest {
            operation_id: identity(&fixture)?.budget_operation_id().as_str().into(),
            account_key: account.clone(),
            authority_threshold: MonetaryAmount {
                units: 5,
                currency: "USD".into(),
            },
            effective_threshold: MonetaryAmount {
                units: 5,
                currency: "USD".into(),
            },
            requested_authorized: MonetaryAmount {
                units: 5,
                currency: "USD".into(),
            },
        });
        let (decision, operation) = fixture.fixture.store.authorize_execution_nonce_preflight(
            &fixture.operation,
            &lease(&fixture)?,
            request.clone(),
            now_ms(),
        )?;
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::ApprovalRequired(_)
        ));
        fixture.operation = operation;
        let budget = fixture.fixture.authority.budget_store();
        for quota in &request.invocation_quotas {
            let usage = budget
                .get_invocation_quota_usage(&quota.key)?
                .ok_or("quota")?;
            assert_eq!(
                (usage.reserved_invocations, usage.captured_invocations),
                (1, 0)
            );
        }
        if approved {
            budget.authorize_cumulative_approval(BudgetAuthorizeCumulativeApprovalRequest {
                capability_id: request.capability_id.clone(),
                grant_index: request.grant_index,
                operation_id: identity(&fixture)?.budget_operation_id().as_str().into(),
                hold_id: identity(&fixture)?.hold_id().as_str().into(),
                admission_binding: request.admission_binding.clone().ok_or("binding")?,
                approval_set_digest: "b".repeat(64),
                event_id: "preflight-approval".into(),
                authority: request.authority.clone(),
            })?;
        }
        reverse(&fixture, 5)?;
        for quota in &request.invocation_quotas {
            let usage = budget
                .get_invocation_quota_usage(&quota.key)?
                .ok_or("quota")?;
            assert_eq!(
                (usage.reserved_invocations, usage.captured_invocations),
                (0, 0)
            );
        }
        let usage = budget
            .get_cumulative_approval_account_usage(&account)?
            .ok_or("approval account")?;
        assert_eq!(usage.reserved_authorized.units, 0);
        assert_eq!(usage.captured_authorized.units, 0);
        let issuance = fixture
            .fixture
            .store
            .issue_execution_nonce_and_commit_admission(
                &issue_command(&fixture)?,
                &fixture.reservation,
                now_ms(),
            );
        if approved {
            fixture.operation = issuance?.into_operation();
            assert!(fixture
                .operation
                .execution_nonce_issuance_digest()
                .is_some());
        } else {
            let error = issuance.expect_err("cleanup is not approval");
            assert!(
                error
                    .to_string()
                    .contains("cannot substitute for required approval"),
                "{error}"
            );
        }
        drop(budget);
        assert!(lifecycle::reopen(fixture).is_ok());
    }
    Ok(())
}
