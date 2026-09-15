use super::*;

fn quota() -> (BudgetInvocationQuotaUsage, BudgetInvocationQuotaMutation) {
    let quota = BudgetInvocationQuota {
        key: BudgetQuotaKey::grant("native-capability", 0),
        max_invocations: 4,
    };
    (
        BudgetInvocationQuotaUsage {
            quota: quota.clone(),
            reserved_invocations: 1,
            captured_invocations: 2,
        },
        BudgetInvocationQuotaMutation {
            quota,
            reserved_invocations_before: 2,
            captured_invocations_before: 1,
            reserved_invocations_after: 1,
            captured_invocations_after: 2,
        },
    )
}

#[test]
fn native_capture_quota_delta_requires_exact_bounded_unique_accounting(
) -> Result<(), BudgetStoreError> {
    let (usage, mutation) = quota();
    verify_capture_quota_delta(
        std::slice::from_ref(&usage),
        std::slice::from_ref(&mutation),
    )?;
    verify_capture_quota_delta(&[], &[])?;
    assert!(verify_capture_quota_delta(std::slice::from_ref(&usage), &[]).is_err());
    assert!(verify_capture_quota_delta(&[], std::slice::from_ref(&mutation)).is_err());
    assert!(verify_capture_quota_delta(
        &[usage.clone(), usage.clone()],
        &[mutation.clone(), mutation.clone()]
    )
    .is_err());
    let count = chio_kernel::budget_store::MAX_INVOCATION_QUOTAS_PER_ADMISSION + 1;
    assert!(verify_capture_quota_delta(
        &vec![usage.clone(); count],
        &vec![mutation.clone(); count]
    )
    .is_err());
    let mutations: [fn(&mut BudgetInvocationQuotaMutation); 5] = [
        |value| value.reserved_invocations_before = 0,
        |value| value.reserved_invocations_after = 0,
        |value| value.captured_invocations_before = u32::MAX,
        |value| value.captured_invocations_after = 0,
        |value| value.quota.max_invocations = 3,
    ];
    for (index, change) in mutations.into_iter().enumerate() {
        let mut changed = mutation.clone();
        change(&mut changed);
        assert!(
            verify_capture_quota_delta(std::slice::from_ref(&usage), &[changed]).is_err(),
            "mutation {index}"
        );
    }
    let usages: [fn(&mut BudgetInvocationQuotaUsage); 4] = [
        |value| value.quota.max_invocations = 2,
        |value| value.reserved_invocations = 2,
        |value| value.captured_invocations = 3,
        |value| value.quota.key.grant_index = Some(1),
    ];
    for (index, change) in usages.into_iter().enumerate() {
        let mut changed = usage.clone();
        change(&mut changed);
        assert!(
            verify_capture_quota_delta(&[changed], std::slice::from_ref(&mutation)).is_err(),
            "usage {index}"
        );
    }
    Ok(())
}

fn amount(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".into(),
    }
}

fn cumulative() -> (
    BudgetCumulativeApprovalUsage,
    BudgetCumulativeApprovalMutation,
) {
    let account_key = BudgetCumulativeApprovalAccountKey {
        authority_id: "native-authority".into(),
        owner_id: "native-owner".into(),
        approval_budget_id: "native-budget".into(),
        approval_budget_epoch: 1,
        root_grant_hash: "a".repeat(64),
        delegation_root_id: None,
        root_binding_digest: None,
        currency: "USD".into(),
    };
    (
        BudgetCumulativeApprovalUsage {
            operation_id: "native-operation".into(),
            account_key: account_key.clone(),
            authority_threshold: amount(100),
            effective_threshold: amount(20),
            requested_authorized: amount(3),
            reserved_authorized_after: amount(7),
            captured_authorized_after: amount(5),
            state: BudgetCumulativeApprovalState::Captured,
            version: 5,
        },
        BudgetCumulativeApprovalMutation {
            operation_id: "native-operation".into(),
            account_key,
            state_before: Some(BudgetCumulativeApprovalState::Authorized),
            state_after: BudgetCumulativeApprovalState::Captured,
            reserved_authorized_before: amount(10),
            captured_authorized_before: amount(2),
            reserved_authorized_after: amount(7),
            captured_authorized_after: amount(5),
            version_before: 4,
            version_after: 5,
        },
    )
}

#[test]
fn native_capture_cumulative_delta_preserves_identity_currency_and_exact_amount(
) -> Result<(), BudgetStoreError> {
    let (usage, mutation) = cumulative();
    verify_capture_cumulative_delta(Some(&usage), Some(&mutation))?;
    verify_capture_cumulative_delta(None, None)?;
    assert!(verify_capture_cumulative_delta(None, Some(&mutation)).is_err());
    assert!(verify_capture_cumulative_delta(Some(&usage), None).is_err());
    let mutations: [fn(&mut BudgetCumulativeApprovalMutation); 14] = [
        |value| value.state_before = None,
        |value| value.state_after = BudgetCumulativeApprovalState::Authorized,
        |value| value.operation_id.push('x'),
        |value| value.account_key.owner_id.push('x'),
        |value| value.reserved_authorized_before.units = 2,
        |value| value.captured_authorized_before.units = u64::MAX,
        |value| value.reserved_authorized_after.units = 8,
        |value| value.captured_authorized_after.units = 6,
        |value| value.version_before = u64::MAX,
        |value| value.version_after = 6,
        |value| value.reserved_authorized_before.currency = "EUR".into(),
        |value| value.captured_authorized_before.currency = "EUR".into(),
        |value| value.reserved_authorized_after.currency = "EUR".into(),
        |value| value.captured_authorized_after.currency = "EUR".into(),
    ];
    for (index, change) in mutations.into_iter().enumerate() {
        let mut changed = mutation.clone();
        change(&mut changed);
        assert!(
            verify_capture_cumulative_delta(Some(&usage), Some(&changed)).is_err(),
            "mutation {index}"
        );
    }
    let usages: [fn(&mut BudgetCumulativeApprovalUsage); 8] = [
        |value| value.state = BudgetCumulativeApprovalState::Authorized,
        |value| value.version = 6,
        |value| value.operation_id.push('x'),
        |value| value.account_key.currency = "EUR".into(),
        |value| value.requested_authorized.units = 4,
        |value| value.requested_authorized.currency = "EUR".into(),
        |value| value.reserved_authorized_after.units = 8,
        |value| value.captured_authorized_after.units = 6,
    ];
    for (index, change) in usages.into_iter().enumerate() {
        let mut changed = usage.clone();
        change(&mut changed);
        assert!(
            verify_capture_cumulative_delta(Some(&changed), Some(&mutation)).is_err(),
            "usage {index}"
        );
    }
    Ok(())
}
