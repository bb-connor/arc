use super::*;

impl SqliteBudgetStore {
    pub(super) fn apply_imported_hold_state(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold_id) = record.hold_id.as_deref() else {
            if matches!(
                record.kind,
                BudgetMutationKind::ReverseExposure | BudgetMutationKind::ReleaseExposure
            ) && Self::has_captured_hold(
                transaction,
                &record.capability_id,
                record.grant_index as usize,
            )? {
                return Err(BudgetStoreError::Invariant(format!(
                    "captured budget hold blocks generic `{}` mutation",
                    record.kind.as_str()
                )));
            }
            return Ok(());
        };

        match record.kind {
            BudgetMutationKind::IncrementInvocation => Ok(()),
            BudgetMutationKind::AuthorizeExposure => {
                if record.allowed == Some(true) {
                    Self::upsert_hold(
                        transaction,
                        hold_id,
                        &record.capability_id,
                        record.grant_index as usize,
                        record.exposure_units,
                        record.exposure_units,
                        false,
                        HoldDisposition::Open,
                        record.authority.as_ref(),
                    )
                } else {
                    Self::delete_hold_if_exists(transaction, hold_id)
                }
            }
            BudgetMutationKind::ReleaseExposure => {
                let hold = Self::load_hold(transaction, hold_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing budget hold `{hold_id}` while importing release event"
                    ))
                })?;
                if hold.capability_id != record.capability_id
                    || hold.grant_index != record.grant_index as usize
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match capability/grant"
                    )));
                }
                if hold.invocation_captured {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was already captured"
                    )));
                }
                let remaining = hold
                    .remaining_exposure_units
                    .checked_sub(record.exposure_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` cannot release more than remaining exposure"
                        ))
                    })?;
                let disposition = if remaining == 0 {
                    HoldDisposition::Released
                } else {
                    HoldDisposition::Open
                };
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    hold.authorized_exposure_units,
                    remaining,
                    hold.invocation_captured,
                    disposition,
                    record.authority.as_ref().or(hold.authority.as_ref()),
                )
            }
            BudgetMutationKind::CancelCapturedBeforeDispatch => {
                if record.allowed != Some(true) {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget captured-before-dispatch cancellation event `{}` was not allowed",
                        record.event_id
                    )));
                }
                let hold = Self::ensure_open_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                )?;
                if !hold.invocation_captured {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was not captured"
                    )));
                }
                if record.exposure_units != hold.authorized_exposure_units
                    || hold.remaining_exposure_units != hold.authorized_exposure_units
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match captured cancellation exposure"
                    )));
                }
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    hold.authorized_exposure_units,
                    0,
                    false,
                    HoldDisposition::Reversed,
                    record.authority.as_ref().or(hold.authority.as_ref()),
                )
            }
            BudgetMutationKind::CaptureInvocation => {
                if record.allowed != Some(true) {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget invocation capture event `{}` was not allowed",
                        record.event_id
                    )));
                }
                let hold = Self::ensure_open_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                )?;
                if !hold.invocation_count_debited {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` has no invocation reservation to capture"
                    )));
                }
                if hold.invocation_captured {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was already captured by another event"
                    )));
                }
                if record.exposure_units != hold.remaining_exposure_units {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match invocation capture exposure"
                    )));
                }
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    hold.authorized_exposure_units,
                    hold.remaining_exposure_units,
                    true,
                    hold.disposition,
                    record.authority.as_ref().or(hold.authority.as_ref()),
                )
            }
            BudgetMutationKind::ReverseExposure => {
                let existing = Self::load_hold(transaction, hold_id)?;
                if existing
                    .as_ref()
                    .is_some_and(|hold| hold.invocation_captured)
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` invocation was already captured"
                    )));
                }
                let authorized_exposure_units = existing
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    authorized_exposure_units,
                    0,
                    false,
                    HoldDisposition::Reversed,
                    record.authority.as_ref(),
                )
            }
            BudgetMutationKind::ReconcileSpend => {
                let existing = Self::load_hold(transaction, hold_id)?;
                let invocation_captured = existing
                    .as_ref()
                    .is_some_and(|hold| hold.invocation_captured);
                let authorized_exposure_units = existing
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    authorized_exposure_units,
                    0,
                    invocation_captured,
                    HoldDisposition::Reconciled,
                    record.authority.as_ref(),
                )
            }
            BudgetMutationKind::ReserveInvocation
            | BudgetMutationKind::AuthorizeCumulativeApproval
            | BudgetMutationKind::ReverseInvocation
            | BudgetMutationKind::CaptureSpend => Err(BudgetStoreError::Invariant(format!(
                "budget mutation `{}` uses state unsupported by the sqlite budget store",
                record.kind.as_str()
            ))),
        }
    }
}
