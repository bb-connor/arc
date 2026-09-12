//! Bounded canonical nonce preflight history and exact relational readback.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityFlowJoinRecordV1, PersistedAdmissionOperationV1,
};

const FORMAT: &str = "chio.native-security-nonce-preflight-join.v1";

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
    pub context: chio_kernel::SecurityInvocationContext,
    pub intent: NativeSecurityNoncePreflightJoinRequestV1,
    pub request: FlowJoinRequest,
    pub result: FlowStateSnapshot,
    pub observed_at: u64,
    pub decision_at: u64,
    pub changes: BoundedVec<crate::security_state::NativeRowChange, 4096>,
    pub current_rows: u64,
    pub current_bytes: u64,
}

impl Record {
    pub(super) fn format() -> String {
        FORMAT.into()
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let bytes = canonical_json_bytes(self).map_err(invalid)?;
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
            return Err(invalid("native nonce preflight record exceeds bounds"));
        }
        Ok(bytes)
    }
    pub(in crate::admission_operation_store::security_participant_state) fn digest(
        &self,
    ) -> Result<String, AdmissionOperationStoreError> {
        let mut bytes = b"chio.native-security-nonce-preflight-join.commit.v1\0".to_vec();
        bytes.extend(self.bytes()?);
        Ok(sha256_hex(&bytes))
    }
    pub(super) fn evidence(
        &self,
        initialized: &SecurityParticipantStateInitialization,
    ) -> Result<NativeSecurityNoncePreflightJoinRecordV1, AdmissionOperationStoreError> {
        if self.authority != initialized.authority || self.initialization != initialized.digest {
            return Err(invalid(
                "native nonce preflight readback changed its initialization",
            ));
        }
        Ok(NativeSecurityNoncePreflightJoinRecordV1 {
            input: self.intent.clone(),
            join: NativeSecurityFlowJoinRecordV1 {
                binding: initialized.admission_binding()?,
                operation_id: self.intent.operation_id().clone(),
                mutation_digest: AdmissionDigest::try_new(
                    "native_nonce_preflight",
                    self.digest()?,
                )?,
                command: self.request.clone(),
                snapshot: self.result.clone(),
            },
        })
    }
    pub(super) fn validate(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        let initialized =
            super::super::records::load_metadata(connection, self.authority.as_str())?
                .ok_or_else(|| invalid("native nonce preflight initialization is absent"))?;
        contract::require_original(
            connection,
            &operation,
            &initialized,
            &self.context,
            &self.intent,
        )?;
        self.intent.validate_resolution(
            operation.binding().operation_id(),
            &self.request,
            &self.result,
        )?;
        if self.schema != FORMAT
            || self.initialization != initialized.digest
            || self.lease.fence.store_uuid != initialized.fence.store_uuid
            || !(1..=9_007_199_254_740_991).contains(&self.sequence)
            || self.current_rows > 65_536
            || self.current_bytes > 67_108_864
            || self.changes.is_empty()
        {
            return Err(invalid("native nonce preflight history is inconsistent"));
        }
        AdmissionDigest::try_new("native_nonce_preflight_previous", &self.previous)?;
        self.lease.validate_operation(
            connection,
            &operation,
            self.observed_at,
            self.decision_at,
        )?;
        for change in self.changes.as_slice() {
            change.validate_flow_join(&self.request).map_err(invalid)?;
        }
        Ok(())
    }
    pub(super) fn insert(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        connection.execute("INSERT INTO security_participant_nonce_preflight_events
            (security_authority_id, sequence, operation_id, tenant_id, transition_id, canonical_record, event_digest, observed_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![self.authority.as_str(),
            i64::try_from(self.sequence).map_err(invalid)?, self.intent.operation_id().as_str(),
            self.intent.key().tenant_id.as_str(), self.intent.transition_id().as_str(), self.bytes()?,
            self.digest()?, i64::try_from(self.observed_at).map_err(invalid)?]).map_err(sqlite_error)?;
        Ok(())
    }
}

pub(in crate::admission_operation_store::security_participant_state) fn head(
    connection: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    let (count,first,last,bytes): (i64,i64,i64,i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MIN(sequence),0), COALESCE(MAX(sequence),0), COALESCE(SUM(length(canonical_record)),0)
         FROM security_participant_nonce_preflight_events WHERE security_authority_id = ?1", [authority],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(sqlite_error)?;
    if !(0..=65_536).contains(&count)
        || count != last
        || (count > 0 && first != 1)
        || !(0..=67_108_864).contains(&bytes)
    {
        return Err(invalid(
            "native nonce preflight chain exceeds bounds or has gaps",
        ));
    }
    u64::try_from(last).map_err(invalid)
}

pub(in crate::admission_operation_store::security_participant_state) fn load(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let bytes: Option<Option<Vec<u8>>> = connection.query_row(
        "SELECT CASE WHEN typeof(canonical_record) = 'blob' AND length(canonical_record) BETWEEN 1 AND 16777216
         THEN canonical_record END FROM security_participant_nonce_preflight_events WHERE security_authority_id = ?1 AND sequence = ?2",
        params![authority,i64::try_from(sequence).map_err(invalid)?], |row| row.get(0)).optional().map_err(sqlite_error)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let bytes = bytes.ok_or_else(|| invalid("native nonce preflight record exceeds bounds"))?;
    let record: Record = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("native nonce preflight is not bounded typed history"))?;
    if record.authority.as_str() != authority
        || record.sequence != sequence
        || record.bytes()? != bytes
    {
        return Err(invalid(
            "native nonce preflight index differs from canonical history",
        ));
    }
    let exact: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_nonce_preflight_events
        WHERE security_authority_id = ?1 AND sequence = ?2 AND operation_id = ?3 AND tenant_id = ?4
        AND transition_id = ?5 AND event_digest = ?6 AND observed_at = ?7)",
            params![
                authority,
                i64::try_from(sequence).map_err(invalid)?,
                record.intent.operation_id().as_str(),
                record.intent.key().tenant_id.as_str(),
                record.intent.transition_id().as_str(),
                record.digest()?,
                i64::try_from(record.observed_at).map_err(invalid)?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !exact {
        return Err(invalid("native nonce preflight relational history differs"));
    }
    record.validate(connection)?;
    Ok(Some(record))
}

pub(in crate::admission_operation_store::security_participant_state) fn load_operation(
    connection: &Connection,
    operation: &AdmissionOperationId,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let located: Option<(Option<String>,i64)> = connection.query_row(
        "SELECT CASE WHEN length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512 THEN security_authority_id END, sequence
         FROM security_participant_nonce_preflight_events WHERE operation_id = ?1", [operation.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(sqlite_error)?;
    let Some((authority, sequence)) = located else {
        return Ok(None);
    };
    let authority =
        authority.ok_or_else(|| invalid("native nonce preflight authority exceeds bounds"))?;
    let record = load(
        connection,
        &authority,
        u64::try_from(sequence).map_err(invalid)?,
    )?
    .ok_or_else(|| invalid("native nonce preflight index has no record"))?;
    if record.intent.operation_id() != operation {
        return Err(invalid("native nonce preflight operation index differs"));
    }
    Ok(Some(record))
}
