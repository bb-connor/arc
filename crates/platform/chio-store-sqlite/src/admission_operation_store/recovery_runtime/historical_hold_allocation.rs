//! A single owed historical hold owns its exact physical workflow event.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkflowHoldAllocation {
    pub(super) workflow_record_version: SafeInteger,
    pub(super) workflow_record_digest: ProjectionDigest,
    pub(super) hold: RecoveryHistoricalHoldV1,
}

impl WorkflowHoldAllocation {
    pub(super) fn verify(
        &self,
        tx: &Connection,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<(), AdmissionOperationStoreError> {
        let key = workflow_key(scope, workflow)?;
        let row =
            raw(tx, &key)?.ok_or_else(|| invariant("recovery historical hold workflow absent"))?;
        let record: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
        let digest: String = tx
            .query_row(
                "SELECT record_digest FROM admission_operation_recovery_events
                 WHERE record_key=?1 AND record_version=?2",
                params![
                    &key,
                    i64::try_from(row.version)
                        .map_err(|_| invariant("recovery hold version exhausted"))?
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if row.kind != "workflow"
            || row.scope != scope_key(scope)?
            || record.scope != *scope
            || record.workflow_id != *workflow
            || record.revision.get() != row.version
            || self.workflow_record_version.get() != row.version
            || hex(self.workflow_record_digest.as_bytes()) != digest
            || record.historical_hold.is_some()
            || record.control == WorkflowControlV1::Quarantined
        {
            return Err(invariant(
                "recovery historical hold workflow anchor changed",
            ));
        }
        super::super::super::historical_holds::verify_operation(tx, &record, &self.hold)
    }
}

/// Read authenticated auxiliary custody without changing the physical workflow.
pub(in crate::admission_operation_store) fn auxiliary_historical_hold(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<Option<RecoveryHistoricalHoldV1>, AdmissionOperationStoreError> {
    let quota = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    let Some(allocation) = quota.native_hold else {
        return Ok(None);
    };
    let physical = raw(tx, &workflow_key(&record.scope, &record.workflow_id)?)?
        .ok_or_else(|| invariant("recovery historical hold workflow absent"))?;
    if physical.payload != encode(record)? {
        return Err(invariant("historical hold requires the physical workflow"));
    }
    Ok(Some(allocation.hold))
}

/// One owed hold unit is independent of the 128 physical native-write units.
pub(in crate::admission_operation_store) fn save_auxiliary_historical_hold(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
    hold: &RecoveryHistoricalHoldV1,
) -> Result<(), AdmissionOperationStoreError> {
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let row =
        raw(tx, &key)?.ok_or_else(|| invariant("recovery historical hold workflow absent"))?;
    if row.payload != encode(record)? || record.historical_hold.is_some() {
        return Err(invariant(
            "historical hold requires unchanged physical custody",
        ));
    }
    let mut quota = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    if let Some(existing) = &quota.native_hold {
        if existing.hold.operation.operation_id() != hold.operation.operation_id()
            || existing.hold.operation.native_admission_digest()
                != hold.operation.native_admission_digest()
            || existing.hold.reason != hold.reason
        {
            return Err(invariant("historical quarantine custody changed"));
        }
        return Ok(());
    }
    let digest: String = tx
        .query_row(
            "SELECT record_digest FROM admission_operation_recovery_events
             WHERE record_key=?1 AND record_version=?2",
            params![
                &key,
                i64::try_from(row.version)
                    .map_err(|_| invariant("recovery hold version exhausted"))?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let allocation = WorkflowHoldAllocation {
        workflow_record_version: SafeInteger::new(row.version)
            .map_err(|_| invariant("recovery hold version exhausted"))?,
        workflow_record_digest: ProjectionDigest::from_bytes(native::decode_hex(&digest)?),
        hold: hold.clone(),
    };
    allocation.verify(tx, &record.scope, &record.workflow_id)?;
    quota.native_hold = Some(allocation);
    save_quota(tx, owner, &quota)
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Exercise one-field substitutions against authenticated actual custody.
    /// No invalid projection, event, payload or baseline is ever published.
    pub fn verify_auxiliary_recovery_hold_faults_for_test(
        &self,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<usize, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(&self.serving_owner.fence))?;
        let record = workflow_tx(&tx, scope, workflow)?;
        let quota = workflow_quota(&tx, scope, workflow)?;
        let original = quota
            .native_hold
            .ok_or_else(|| invariant("hold fault fixture absent"))?;
        original.verify(&tx, scope, workflow)?;
        let intent = record
            .admission
            .as_ref()
            .ok_or_else(|| invariant("hold fault fixture intent absent"))?;
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
        let native = load_by_operation_id_tx(&tx, binding.operation_id())?
            .ok_or_else(|| invariant("hold fault fixture native absent"))?;
        let mut cases = Vec::new();
        let mut changed = original.clone();
        changed.workflow_record_version =
            SafeInteger::new(original.workflow_record_version.get() + 1)
                .map_err(|_| invariant("hold fault fixture version exhausted"))?;
        cases.push((changed, "recovery historical hold workflow anchor changed"));
        let mut changed = original.clone();
        let mut digest = *changed.workflow_record_digest.as_bytes();
        digest[0] ^= 1;
        changed.workflow_record_digest = ProjectionDigest::from_bytes(digest);
        cases.push((changed, "recovery historical hold workflow anchor changed"));
        let mut changed = original.clone();
        changed.hold.operation = OperationRef::new(
            OperationId::new("another-captured-operation")
                .map_err(|_| invariant("hold fault fixture identifier refused"))?,
            original.hold.operation.native_admission_digest(),
            original.hold.operation.operation_version(),
        )
        .map_err(|_| invariant("hold fault fixture reference refused"))?;
        cases.push((changed, "historical hold native identity changed"));
        let mut changed = original.clone();
        let mut digest = *original.hold.operation.native_admission_digest().as_bytes();
        digest[0] ^= 1;
        changed.hold.operation = OperationRef::new(
            original.hold.operation.operation_id().clone(),
            NativeAdmissionDigest::from_bytes(digest),
            original.hold.operation.operation_version(),
        )
        .map_err(|_| invariant("hold fault fixture reference refused"))?;
        cases.push((changed, "historical hold native identity changed"));
        let mut changed = original.clone();
        changed.hold.operation = OperationRef::new(
            original.hold.operation.operation_id().clone(),
            original.hold.operation.native_admission_digest(),
            SafeInteger::new(native.operation.version() + 1)
                .map_err(|_| invariant("hold fault fixture version exhausted"))?,
        )
        .map_err(|_| invariant("hold fault fixture reference refused"))?;
        cases.push((changed, "historical hold native identity changed"));
        let count = cases.len();
        for (changed, expected) in cases {
            if !matches!(changed.verify(&tx, scope, workflow), Err(AdmissionOperationStoreError::Invariant(message)) if message == expected)
            {
                return Err(invariant(
                    "hold ownership substitution was not exactly refused",
                ));
            }
        }
        let mut foreign = scope.clone();
        foreign.process_id = ProcessId::new("foreign-hold-process")
            .map_err(|_| invariant("hold fault fixture scope refused"))?;
        if !matches!(original.verify(&tx, &foreign, workflow), Err(AdmissionOperationStoreError::Invariant(message)) if message == "recovery historical hold workflow absent")
        {
            return Err(invariant(
                "hold ownership foreign scope was not exactly refused",
            ));
        }
        let mut conflict = original.hold.clone();
        conflict.reason =
            if conflict.reason == RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable {
                RecoveryHistoricalHoldReasonV1::FrozenOutputVerifierUnavailable
            } else {
                RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable
            };
        if !matches!(save_auxiliary_historical_hold(&tx, &self.serving_owner, &record, &conflict), Err(AdmissionOperationStoreError::Invariant(message)) if message == "historical quarantine custody changed")
        {
            return Err(invariant("hold reason replacement was not exactly refused"));
        }
        tx.commit().map_err(sqlite_error)?;
        Ok(count + 2)
    }
}
