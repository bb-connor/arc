//! Preflight every participant before publishing an in-memory reservation change.
use super::*;

pub(super) struct PreparedAccounting {
    quotas: Vec<(BudgetQuotaKey, BudgetInvocationQuotaState)>,
    cumulative: Option<(
        BudgetCumulativeApprovalAccountKey,
        BudgetCumulativeApprovalAccountState,
    )>,
}

#[derive(Clone, Copy)]
enum Transition {
    Capture,
    Reverse { captured: bool },
}

impl Transition {
    fn quota(
        self,
        mut state: BudgetInvocationQuotaState,
    ) -> Result<BudgetInvocationQuotaState, BudgetStoreError> {
        let reserved = InvocationCount::new(state.reserved_invocations);
        let captured = InvocationCount::new(state.captured_invocations);
        if reserved.try_add(captured)?.get() > state.max_invocations {
            return Err(BudgetStoreError::Invariant(
                "invocation quota exceeds its maximum".into(),
            ));
        }
        match self {
            Self::Capture => {
                state.reserved_invocations = reserved.try_sub(InvocationCount::ONE)?.get();
                state.captured_invocations = captured.try_add(InvocationCount::ONE)?.get();
            }
            Self::Reverse { captured: true } => {
                state.captured_invocations = captured.try_sub(InvocationCount::ONE)?.get();
            }
            Self::Reverse { captured: false } => {
                state.reserved_invocations = reserved.try_sub(InvocationCount::ONE)?.get();
            }
        }
        Ok(state)
    }

    fn cumulative(
        self,
        mut state: BudgetCumulativeApprovalAccountState,
        amount: u64,
    ) -> Result<BudgetCumulativeApprovalAccountState, BudgetStoreError> {
        let reserved = ExposureUnits::new(state.reserved_authorized_units);
        let captured = ExposureUnits::new(state.captured_authorized_units);
        reserved.try_add(captured)?;
        let amount = ExposureUnits::new(amount);
        match self {
            Self::Capture => {
                state.reserved_authorized_units = reserved.try_sub(amount)?.get();
                state.captured_authorized_units = captured.try_add(amount)?.get();
            }
            Self::Reverse { captured: true } => {
                state.captured_authorized_units = captured.try_sub(amount)?.get()
            }
            Self::Reverse { captured: false } => {
                state.reserved_authorized_units = reserved.try_sub(amount)?.get()
            }
        }
        state.version = state.version.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("cumulative approval account version overflowed u64".into())
        })?;
        Ok(state)
    }
}

impl InMemoryBudgetStoreInner {
    pub(super) fn prepare_capture_accounting(
        &self,
        hold: &BudgetHoldState,
    ) -> Result<PreparedAccounting, BudgetStoreError> {
        self.prepare_accounting(
            &hold.invocation_quotas,
            hold.cumulative_approval.as_ref(),
            |_| Transition::Capture,
            Transition::Capture,
        )
    }

    pub(super) fn prepare_reversal_accounting(
        &self,
        quotas: &[BudgetInvocationQuota],
        hold: Option<&BudgetHoldState>,
        cancels_captured: bool,
    ) -> Result<PreparedAccounting, BudgetStoreError> {
        let cumulative = hold.and_then(|hold| hold.cumulative_approval.as_ref());
        self.prepare_accounting(
            quotas,
            cumulative,
            |quota| Transition::Reverse {
                captured: hold.is_none()
                    || cancels_captured
                    || hold.is_some_and(|hold| {
                        hold.legacy_captured_invocation_quota.as_ref() == Some(quota)
                    }),
            },
            Transition::Reverse {
                captured: cumulative.is_some_and(|participant| {
                    participant.state == BudgetCumulativeApprovalState::Captured
                }),
            },
        )
    }

    fn prepare_accounting(
        &self,
        quotas: &[BudgetInvocationQuota],
        participant: Option<&BudgetCumulativeApprovalHoldState>,
        quota_transition: impl Fn(&BudgetInvocationQuota) -> Transition,
        cumulative_transition: Transition,
    ) -> Result<PreparedAccounting, BudgetStoreError> {
        let quotas = quotas
            .iter()
            .map(|quota| {
                let state = self.invocation_quotas.get(&quota.key).ok_or_else(|| {
                    BudgetStoreError::Invariant("missing invocation quota".into())
                })?;
                if state.max_invocations != quota.max_invocations {
                    return Err(BudgetStoreError::Invariant(
                        "invocation quota maximum changed".into(),
                    ));
                }
                Ok((
                    quota.key.clone(),
                    quota_transition(quota).quota(state.clone())?,
                ))
            })
            .collect::<Result<_, BudgetStoreError>>()?;
        let cumulative = participant
            .map(|participant| {
                let key = &participant.request.account_key;
                let state = self.cumulative_approval_accounts.get(key).ok_or_else(|| {
                    BudgetStoreError::Invariant("missing cumulative approval account".into())
                })?;
                Ok::<_, BudgetStoreError>((
                    key.clone(),
                    cumulative_transition.cumulative(
                        state.clone(),
                        participant.request.requested_authorized.units,
                    )?,
                ))
            })
            .transpose()?;
        Ok(PreparedAccounting { quotas, cumulative })
    }
}

impl PreparedAccounting {
    pub(super) fn apply(self, store: &mut InMemoryBudgetStoreInner) {
        for (key, state) in self.quotas {
            store.invocation_quotas.insert(key, state);
        }
        if let Some((key, state)) = self.cumulative {
            store.cumulative_approval_accounts.insert(key, state);
        }
    }
}
