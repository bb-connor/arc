//! Captured historical holds preserve physical workflow bytes and ownership.
use super::*;

pub(in crate::admission_operation_store) const SQL: &str = include_str!("historical_holds.sql");

/// This check has no quota lookup, so metadata authentication cannot recurse.
pub(super) fn verify_operation(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    hold: &RecoveryHistoricalHoldV1,
) -> Result<(), AdmissionOperationStoreError> {
    let intent = record
        .admission
        .as_ref()
        .ok_or_else(|| invariant("historical hold native intent absent"))?;
    let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
    let stored = load_by_operation_id_tx(tx, binding.operation_id())?
        .ok_or_else(|| invariant("historical hold native operation absent"))?;
    let reference = native::operation_ref(&stored.operation)?;
    if stored.operation.binding() != &binding
        || hold.operation.operation_id() != reference.operation_id()
        || hold.operation.native_admission_digest() != reference.native_admission_digest()
        || hold.operation.operation_version().get() > reference.operation_version().get()
    {
        return Err(invariant("historical hold native identity changed"));
    }
    native::verify_physical_capture(tx, record, &stored.operation)?;
    Ok(())
}

/// Old in-row custody and new auxiliary custody are mutually exclusive.
pub(super) fn effective(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<Option<RecoveryHistoricalHoldV1>, AdmissionOperationStoreError> {
    let auxiliary = auxiliary_historical_hold(tx, record)?;
    require_exclusive(record.historical_hold.as_ref(), auxiliary.as_ref())?;
    match (&record.historical_hold, auxiliary) {
        (Some(_), Some(_)) => Err(invariant("historical hold has two physical owners")),
        (Some(hold), None) => {
            if record.control != WorkflowControlV1::Quarantined {
                return Err(invariant("historical in-row hold control changed"));
            }
            verify_operation(tx, record, hold)?;
            Ok(Some(hold.clone()))
        }
        (None, Some(hold)) => {
            verify_operation(tx, record, &hold)?;
            Ok(Some(hold))
        }
        (None, None) => {
            if record.control == WorkflowControlV1::Quarantined {
                return Err(invariant("historical quarantine lost its custody"));
            }
            Ok(None)
        }
    }
}

fn require_exclusive(
    in_row: Option<&RecoveryHistoricalHoldV1>,
    auxiliary: Option<&RecoveryHistoricalHoldV1>,
) -> Result<(), AdmissionOperationStoreError> {
    if in_row.is_some() && auxiliary.is_some() {
        return Err(invariant("historical hold has two physical owners"));
    }
    Ok(())
}

pub(super) fn require_unheld(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if effective(tx, record)?.is_some() {
        return Err(invariant("recovery workflow is historically quarantined"));
    }
    Ok(())
}

/// Only original private finalization may discharge the old signer-only hold.
/// Fresh dispatch, current result release and every other hold keep require_unheld.
pub(super) fn blocks_original_private_settlement(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<bool, AdmissionOperationStoreError> {
    Ok(effective(tx, record)?.is_some_and(|hold| {
        hold.reason != RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable
    }))
}

/// Authenticate retained hold data without reading the quota's terminal pointer.
/// This is not an effective-workflow view or permission to bypass a hold.
pub(super) fn retained_hold_data(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<Option<RecoveryHistoricalHoldV1>, AdmissionOperationStoreError> {
    let workflow = workflow_key(&record.scope, &record.workflow_id)?;
    let row = raw_checked(tx, &workflow)?
        .ok_or_else(|| invariant("private settlement hold workflow absent"))?;
    let source = source_reference(tx, &workflow)?;
    if row.payload != encode(record)? || row.version != record.revision.get() {
        return Err(invariant(
            "private settlement hold physical workflow changed",
        ));
    }
    let key = format!(
        "workflow-quota:{}:{}",
        scope_key(&record.scope)?,
        record.workflow_id.as_str()
    );
    let auxiliary = if let Some(quota) = raw_checked(tx, &key)? {
        source_reference(tx, &key)?;
        if quota.kind != "command" || quota.scope != scope_key(&record.scope)? {
            return Err(invariant("private settlement hold quota source changed"));
        }
        let value: serde_json::Value = decode(&quota.payload)?;
        match value.get("native_hold").filter(|value| !value.is_null()) {
            None => None,
            Some(allocation) => {
                let version: SafeInteger = serde_json::from_value(
                    allocation
                        .get("workflow_record_version")
                        .cloned()
                        .ok_or_else(|| {
                            invariant("private settlement hold workflow version absent")
                        })?,
                )
                .map_err(|_| invariant("private settlement hold workflow version refused"))?;
                let digest: ProjectionDigest = serde_json::from_value(
                    allocation
                        .get("workflow_record_digest")
                        .cloned()
                        .ok_or_else(|| {
                            invariant("private settlement hold workflow digest absent")
                        })?,
                )
                .map_err(|_| invariant("private settlement hold workflow digest refused"))?;
                if version.get() != row.version || &digest != source.digest() {
                    return Err(invariant("private settlement hold workflow anchor changed"));
                }
                Some(
                    serde_json::from_value::<RecoveryHistoricalHoldV1>(
                        allocation
                            .get("hold")
                            .cloned()
                            .ok_or_else(|| invariant("private settlement retained hold absent"))?,
                    )
                    .map_err(|_| invariant("private settlement retained hold refused"))?,
                )
            }
        }
    } else {
        None
    };
    require_exclusive(record.historical_hold.as_ref(), auxiliary.as_ref())?;
    let hold = record.historical_hold.clone().or(auxiliary);
    if let Some(hold) = &hold {
        verify_operation(tx, record, hold)?;
    }
    Ok(hold)
}

/// Only authorized outward reads receive this clone. Writers retain raw records.
pub(super) fn view(
    tx: &Connection,
    record: RecoveryWorkflowRecordV1,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    let hold = effective(tx, &record)?;
    let signer_hold_discharged =
        hold.as_ref().is_some_and(|hold| {
            hold.reason == RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable
        }) && super::terminal_custody::private_settlement_committed(tx, &record)?;
    let mut record = super::terminal_custody::view(tx, record)?;
    if let Some(hold) = hold {
        if signer_hold_discharged
            && record.admission_closed
            && matches!(record.effect, EffectObservationV1::Complete { .. })
        {
            // The signed original/current settlement was independently read
            // back. The old physical hold remains immutable audit data.
            record.control = WorkflowControlV1::Active;
            record.historical_hold = None;
            return Ok(record);
        }
        record.control = WorkflowControlV1::Quarantined;
        record.historical_hold = Some(hold);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_hold_requires_one_physical_representation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let hold = RecoveryHistoricalHoldV1 {
            operation: OperationRef::new(
                OperationId::new("a")?,
                NativeAdmissionDigest::from_bytes([3; 32]),
                SafeInteger::new(1)?,
            )?,
            reason: RecoveryHistoricalHoldReasonV1::LegacyDeploymentUnavailable,
        };
        require_exclusive(None, None)?;
        require_exclusive(Some(&hold), None)?;
        require_exclusive(None, Some(&hold))?;
        assert!(require_exclusive(Some(&hold), Some(&hold)).is_err());
        Ok(())
    }
}
