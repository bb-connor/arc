//! Historical command custody and row deltas, rooted in immutable hydration.
use super::*;
use crate::security_state::NativeRowChange;
use chio_kernel::admission_operation::{
    NativeSecurityFlowJoinRecordV1, NativeSecurityInputJoinRecordV1,
    NativeSecurityInputJoinRequestV1, PersistedAdmissionOperationV1,
};
use chio_kernel::SecurityInvocationContext;
use chio_security_types::ports::{BoundedVec, FlowJoinRequest, FlowStateSnapshot};

mod lease;
pub(super) mod ordered;
mod rows;
pub(super) use rows::verify_rows;

pub(super) const MUTATION: &str = "join_security_participant_flow";
const FORMAT: &str = "chio.native-security-flow-join.v1";
const INPUT_FORMAT: &str = "chio.native-security-flow-join.v2";
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LeaseHistory {
    claimant: AdmissionIdentifier,
    lease_id: AdmissionIdentifier,
    expires_at: u64,
    pub fence: StoreMutationFence,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub schema: String,
    pub authority: AdmissionIdentifier,
    pub sequence: u64,
    pub initialization: String,
    pub previous: String,
    pub operation: PersistedAdmissionOperationV1,
    pub lease: LeaseHistory,
    pub context: SecurityInvocationContext,
    // Preserve v1 canonical bytes. V2 explicitly retains classified-input intent;
    // neither a transition prefix nor a resolved command can infer that intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<NativeSecurityInputJoinRequestV1>,
    pub request: FlowJoinRequest,
    pub result: FlowStateSnapshot,
    pub observed_at: u64,
    pub decision_at: u64,
    pub changes: BoundedVec<NativeRowChange, 4096>,
    pub current_rows: u64,
    pub current_bytes: u64,
}

impl LeaseHistory {
    pub(super) fn new(lease: &AdmissionRecoveryLease) -> Self {
        Self {
            claimant: lease.claimant_id().clone(),
            lease_id: lease.coordinator_lease_id().clone(),
            expires_at: lease.expires_at_unix_ms(),
            fence: lease.store_fence().clone(),
        }
    }
}

impl Record {
    pub(super) fn join_record(
        &self,
        initialized: &SecurityParticipantStateInitialization,
    ) -> Result<NativeSecurityFlowJoinRecordV1, AdmissionOperationStoreError> {
        if self.authority != initialized.authority || self.initialization != initialized.digest {
            return Err(invalid("native join initialization differs from history"));
        }
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        Ok(NativeSecurityFlowJoinRecordV1 {
            binding: initialized.admission_binding()?,
            operation_id: operation.binding().operation_id().clone(),
            mutation_digest: AdmissionDigest::try_new("native_mutation_digest", self.digest()?)?,
            command: self.request.clone(),
            snapshot: self.result.clone(),
        })
    }

    pub(super) fn input_record(
        &self,
        initialized: &SecurityParticipantStateInitialization,
    ) -> Result<NativeSecurityInputJoinRecordV1, AdmissionOperationStoreError> {
        let record = NativeSecurityInputJoinRecordV1 {
            input: self
                .input
                .clone()
                .ok_or_else(|| invalid("raw native join is not an input join"))?,
            join: self.join_record(initialized)?,
        };
        record.validate()?;
        Ok(record)
    }

    pub(super) fn bytes(&self) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let bytes = canonical_json_bytes(self).map_err(invalid)?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("native mutation record exceeds bounds"));
        }
        Ok(bytes)
    }

    pub(super) fn digest(&self) -> Result<String, AdmissionOperationStoreError> {
        let mut bytes = b"chio.native-security-mutation.commit.v1\0".to_vec();
        bytes.extend(self.bytes()?);
        Ok(sha256_hex(&bytes))
    }

    pub(super) fn insert(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        connection.execute(
            "INSERT INTO security_participant_state_mutations
             (security_authority_id, sequence, operation_id, tenant_id, transition_id, canonical_record, mutation_digest, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![self.authority.as_str(), i64::try_from(self.sequence).map_err(invalid)?,
                operation.binding().operation_id().as_str(), self.request.key.tenant_id.as_str(),
                self.request.transition_id.as_str(), self.bytes()?, self.digest()?, i64::try_from(self.observed_at).map_err(invalid)?],
        ).map_err(sqlite_error)?;
        Ok(())
    }

    pub(super) fn validate(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        let original = super::mutations::require_request(
            connection,
            &operation,
            &self.context,
            &self.request.key,
        )?;
        match (self.schema.as_str(), &self.input) {
            (FORMAT, None) => (),
            (INPUT_FORMAT, Some(input)) => {
                // Only raw v1 history may predate original native selection.
                // A new-format event must retain the writer's original custody
                // requirements when reopened, not just its resolved labels.
                if original.native_security_authority_binding().is_none()
                    || original.authority_profile().is_none()
                {
                    return Err(invalid(
                        "native input history lacks original authority custody",
                    ));
                }
                input.validate_resolution(
                    operation.binding().operation_id(),
                    &self.request,
                    &self.result,
                )?;
            }
            _ => return Err(invalid("native join schema and command family differ")),
        }
        if original.native_security_authority_binding().is_some() {
            // These are historical equality checks, not present authority.
            // Initialization-chain and lease-commit verification independently
            // bind these fields to their original anchored records.
            original.validate_native_security_authority(
                &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1::new(
                    AdmissionIdentifier::try_new(
                        "native_store_uuid",
                        self.lease.fence.store_uuid.clone(),
                    )?,
                    self.authority.clone(),
                    AdmissionDigest::try_new(
                        "native_initialization_digest",
                        self.initialization.clone(),
                    )?,
                ),
            )?;
        }
        super::super::schema::validate_trusted_time(self.observed_at, "native mutation time")?;
        super::super::schema::validate_trusted_time(self.decision_at, "native decision time")?;
        for change in self.changes.as_slice() {
            change.validate_flow_join(&self.request).map_err(invalid)?;
        }
        if self.observed_at.abs_diff(self.decision_at) > MAX_TRUSTED_CLOCK_SKEW_MS
            || self.current_rows > 65_536
            || self.current_bytes > 67_108_864
            || self.sequence < 2
            || self.sequence > 9_007_199_254_740_991
            || self.result.key != self.request.key
            || self.changes.is_empty()
            || self.changes.as_slice().iter().any(|change| {
                change.after.is_none()
                    || !crate::security_state::is_native_flow_join_table(&change.table)
            })
            || self.result.context_generation == 0
            || self.result.context_generation > 9_007_199_254_740_991
            || self
                .result
                .principal_label
                .join_restrictions(&self.request.principal_join)
                .map_err(invalid)?
                != self.result.principal_label
            || self
                .result
                .lineage_label
                .join_restrictions(&self.request.lineage_join)
                .map_err(invalid)?
                != self.result.lineage_label
            || self
                .result
                .session_label
                .join_restrictions(&self.request.session_join)
                .map_err(invalid)?
                != self.result.session_label
        {
            return Err(invalid("native mutation command or result is malformed"));
        }
        self.lease
            .validate_operation(connection, &operation, self.observed_at, self.decision_at)
    }
}

pub(super) fn format(input: bool) -> String {
    if input {
        INPUT_FORMAT.into()
    } else {
        FORMAT.into()
    }
}

pub(super) fn load(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    // Never allocate untrusted relational text before bounding it. Read only
    // the bounded canonical artifact, then compare typed metadata in SQLite.
    let row: Option<Option<Vec<u8>>> = connection.query_row(
        "SELECT CASE WHEN typeof(canonical_record) = 'blob' AND length(canonical_record) BETWEEN 1 AND 16777216
         AND length(CAST(mutation_digest AS BLOB)) = 64
         AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 512
         AND length(CAST(tenant_id AS BLOB)) BETWEEN 1 AND 512
         AND length(CAST(transition_id AS BLOB)) BETWEEN 1 AND 512
         THEN canonical_record END FROM security_participant_state_mutations
         WHERE security_authority_id = ?1 AND sequence = ?2",
        params![authority, i64::try_from(sequence).map_err(invalid)?],
        |row| row.get(0),
    ).optional().map_err(sqlite_error)?;
    let Some(bytes) = row else {
        return Ok(None);
    };
    let bytes = bytes.ok_or_else(|| invalid("native mutation record exceeds bounds"))?;
    let record: Record = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("native mutation record is not bounded typed data"))?;
    let operation = AdmissionOperationV1::from_persisted(record.operation.clone())?;
    if record.authority.as_str() != authority
        || record.sequence != sequence
        || record.bytes()? != bytes
    {
        return Err(invalid(
            "native mutation projection differs from canonical history",
        ));
    }
    let exact: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_state_mutations
         WHERE security_authority_id = ?1 AND sequence = ?2 AND mutation_digest = ?3
           AND operation_id = ?4 AND tenant_id = ?5 AND transition_id = ?6 AND observed_at = ?7)",
            params![
                authority,
                i64::try_from(sequence).map_err(invalid)?,
                record.digest()?,
                operation.binding().operation_id().as_str(),
                record.request.key.tenant_id.as_str(),
                record.request.transition_id.as_str(),
                i64::try_from(record.observed_at).map_err(invalid)?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !exact {
        return Err(invalid(
            "native mutation metadata differs from canonical history",
        ));
    }
    record.validate(connection)?;
    Ok(Some(record))
}

pub(super) fn head(
    connection: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    let (count, sequence, bytes): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(sequence), 1), COALESCE(SUM(length(canonical_record)), 0)
         FROM security_participant_state_mutations WHERE security_authority_id = ?1",
        [authority], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(sqlite_error)?;
    if !(0..=65_536).contains(&count) || sequence != count + 1 || !(0..=67_108_864).contains(&bytes)
    {
        return Err(invalid(
            "native mutation history is incomplete or exceeds bounds",
        ));
    }
    u64::try_from(sequence).map_err(invalid)
}

pub(super) fn load_for_operation(
    connection: &Connection,
    operation: &AdmissionOperationId,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let located: Option<(Option<String>, i64)> = connection.query_row(
        "SELECT CASE WHEN length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512
         THEN security_authority_id END, sequence FROM security_participant_state_mutations WHERE operation_id = ?1",
        [operation.as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(sqlite_error)?;
    let Some((authority, sequence)) = located else {
        return Ok(None);
    };
    let authority = authority.ok_or_else(|| invalid("native mutation authority exceeds bounds"))?;
    let record = load(
        connection,
        &authority,
        u64::try_from(sequence).map_err(invalid)?,
    )?
    .ok_or_else(|| invalid("native mutation index has no record"))?;
    Ok(Some(record))
}
