//! Canonical, bounded egress history with independent operation-lease evidence.
use super::*;
use chio_kernel::admission_operation::PersistedAdmissionOperationV1;

const FORMAT: &str = "chio.native-security-egress.v1";
const DECLASSIFIED_FORMAT: &str = "chio.native-security-egress.v2";
const MAX_RECORD: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store::security_participant_state) struct Record {
    pub schema: String,
    pub authority: AdmissionIdentifier,
    pub sequence: u64,
    pub initialization: String,
    pub previous: String,
    pub operation: PersistedAdmissionOperationV1,
    pub lease: super::super::history::LeaseHistory,
    pub context: SecurityInvocationContext,
    pub command: NativeEgressCommand,
    pub result: NativeEgressResult,
    pub live_request_hash: AdmissionDigest,
    pub acquisition_digest: Option<AdmissionDigest>,
    pub observed_at: u64,
    pub decision_at: u64,
    pub changes: BoundedVec<crate::security_state::NativeRowChange, 4>,
    pub current_rows: u64,
    pub current_bytes: u64,
}

impl Record {
    pub(in crate::admission_operation_store::security_participant_state) fn format(
        command: &NativeEgressCommand,
    ) -> String {
        if matches!(command, NativeEgressCommand::CommitDeclassified { .. }) {
            DECLASSIFIED_FORMAT.into()
        } else {
            FORMAT.into()
        }
    }
    pub(in crate::admission_operation_store::security_participant_state) fn mutation(
        &self,
    ) -> &'static str {
        match self.command {
            NativeEgressCommand::Acquire(_) => "acquire_security_participant_egress",
            NativeEgressCommand::Commit(_) | NativeEgressCommand::CommitDeclassified { .. } => {
                "commit_security_participant_egress"
            }
        }
    }
    pub(in crate::admission_operation_store::security_participant_state) fn bytes(
        &self,
    ) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let bytes = canonical_json_bytes(self).map_err(invalid)?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD {
            return Err(invalid("native egress record exceeds bounds"));
        }
        Ok(bytes)
    }
    pub(in crate::admission_operation_store::security_participant_state) fn digest(
        &self,
    ) -> Result<String, AdmissionOperationStoreError> {
        let mut bytes = b"chio.native-security-egress.commit.v1\0".to_vec();
        bytes.extend(self.bytes()?);
        Ok(sha256_hex(&bytes))
    }
    pub(in crate::admission_operation_store::security_participant_state) fn validate(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        let initialized =
            super::super::records::load_metadata(connection, self.authority.as_str())?
                .ok_or_else(|| invalid("native egress initialization is absent"))?;
        let fence = self.command.fence().map_err(invalid)?;
        let original = contract::require_original(
            connection,
            &operation,
            &self.context,
            &initialized.admission_binding()?,
            &fence,
        )?;
        contract::validate_declassification_binding(&original, &self.command)?;
        if self.schema != Self::format(&self.command)
            || self.initialization != initialized.digest
            || self.lease.fence.store_uuid != initialized.fence.store_uuid
            || !(1..=9_007_199_254_740_991).contains(&self.sequence)
            || self.current_rows > 65_536
            || self.current_bytes > 67_108_864
            || self.result != self.command.expected_result().map_err(invalid)?
            || self.changes.len() != self.command.expected_changes()
        {
            return Err(invalid("native egress command history is inconsistent"));
        }
        AdmissionDigest::try_new("native_egress_previous", &self.previous)?;
        self.command
            .validate_observation(self.observed_at.max(self.decision_at))
            .map_err(invalid)?;
        self.lease.validate_operation(
            connection,
            &operation,
            self.observed_at,
            self.decision_at,
        )?;
        self.command
            .validate_changes(self.changes.as_slice())
            .map_err(invalid)?;
        match &self.command {
            NativeEgressCommand::Acquire(_) => {
                if self.acquisition_digest.is_some() {
                    return Err(invalid(
                        "first egress acquisition cannot adopt earlier custody",
                    ));
                }
            }
            NativeEgressCommand::Commit(_) | NativeEgressCommand::CommitDeclassified { .. } => {
                let acquired =
                    load_operation(connection, operation.binding().operation_id(), "acquired")?
                        .ok_or_else(|| invalid("native egress commit has no owned acquisition"))?;
                if acquired.authority != self.authority
                    || acquired.initialization != self.initialization
                    || acquired.sequence >= self.sequence
                    || acquired.live_request_hash != self.live_request_hash
                    || acquired.command.fence().map_err(invalid)? != fence
                    || acquired.observed_at > self.observed_at
                    || acquired.decision_at > self.decision_at
                    || self
                        .acquisition_digest
                        .as_ref()
                        .map(AdmissionDigest::as_str)
                        != Some(acquired.digest()?.as_str())
                {
                    return Err(invalid(
                        "native egress commit replaced its acquired custody",
                    ));
                }
            }
        }
        Ok(())
    }
    pub(in crate::admission_operation_store::security_participant_state) fn insert(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        let fence = self.command.fence().map_err(invalid)?;
        connection.execute("INSERT INTO security_participant_egress_events
          (security_authority_id, sequence, operation_id, phase, tenant_id, request_id, fence_id, canonical_record, event_digest, observed_at)
          VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![self.authority.as_str(), i64::try_from(self.sequence).map_err(invalid)?, operation.binding().operation_id().as_str(), self.command.phase(), fence.key.tenant_id.as_str(), fence.request_id.as_str(), fence.fence_id.as_str(), self.bytes()?, self.digest()?, i64::try_from(self.observed_at).map_err(invalid)?]).map_err(sqlite_error)?;
        Ok(())
    }
}

pub(in crate::admission_operation_store::security_participant_state) fn head(
    connection: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    let (count, first, last, bytes): (i64,i64,i64,i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MIN(sequence),0), COALESCE(MAX(sequence),0), COALESCE(SUM(length(canonical_record)),0)
         FROM security_participant_egress_events WHERE security_authority_id = ?1", [authority], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(sqlite_error)?;
    if !(0..=65_536).contains(&count)
        || count != last
        || (count > 0 && first != 1)
        || !(0..=67_108_864).contains(&bytes)
    {
        return Err(invalid("native egress chain exceeds bounds or has gaps"));
    }
    u64::try_from(last).map_err(invalid)
}

pub(in crate::admission_operation_store::security_participant_state) fn load(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let row: Option<Option<Vec<u8>>> = connection.query_row(
        "SELECT CASE WHEN typeof(canonical_record) = 'blob' AND length(canonical_record) BETWEEN 1 AND 16777216
          AND length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512 THEN canonical_record END
         FROM security_participant_egress_events WHERE security_authority_id = ?1 AND sequence = ?2",
        params![authority, i64::try_from(sequence).map_err(invalid)?], |row| row.get(0)).optional().map_err(sqlite_error)?;
    let Some(bytes) = row else {
        return Ok(None);
    };
    let bytes = bytes.ok_or_else(|| invalid("native egress record exceeds bounds"))?;
    let record: Record = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("native egress is not bounded typed history"))?;
    if record.bytes()? != bytes
        || record.authority.as_str() != authority
        || record.sequence != sequence
    {
        return Err(invalid(
            "native egress index differs from canonical history",
        ));
    }
    let operation = AdmissionOperationV1::from_persisted(record.operation.clone())?;
    let fence = record.command.fence().map_err(invalid)?;
    let exact: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM security_participant_egress_events
        WHERE security_authority_id = ?1 AND sequence = ?2 AND operation_id = ?3 AND phase = ?4
          AND tenant_id = ?5 AND request_id = ?6 AND fence_id = ?7 AND event_digest = ?8 AND observed_at = ?9)",
        params![authority, i64::try_from(sequence).map_err(invalid)?, operation.binding().operation_id().as_str(), record.command.phase(), fence.key.tenant_id.as_str(), fence.request_id.as_str(), fence.fence_id.as_str(), record.digest()?, i64::try_from(record.observed_at).map_err(invalid)?], |row| row.get(0)).map_err(sqlite_error)?;
    if !exact {
        return Err(invalid("native egress index is inconsistent"));
    }
    record.validate(connection)?;
    Ok(Some(record))
}

pub(in crate::admission_operation_store::security_participant_state) fn load_operation(
    connection: &Connection,
    operation: &AdmissionOperationId,
    phase: &str,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let located: Option<(Option<String>, i64)> = connection.query_row(
        "SELECT CASE WHEN length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512 THEN security_authority_id END, sequence
         FROM security_participant_egress_events WHERE operation_id = ?1 AND phase = ?2", params![operation.as_str(),phase], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(sqlite_error)?;
    let Some((authority, sequence)) = located else {
        return Ok(None);
    };
    let authority = authority.ok_or_else(|| invalid("native egress authority exceeds bounds"))?;
    let record = load(
        connection,
        &authority,
        u64::try_from(sequence).map_err(invalid)?,
    )?
    .ok_or_else(|| invalid("native egress index has no record"))?;
    Ok(Some(record))
}
