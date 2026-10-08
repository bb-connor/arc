//! An immutable account marker records complete fenced reference activation.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::ReferenceCutoff;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct ReferenceAccount {
    pub(in crate::admission_operation_store) authority_domain: AuthorityDomainId,
    pub(in crate::admission_operation_store) tenant_id: RecoveryTenantId,
}

impl ReferenceAccount {
    pub(in crate::admission_operation_store) fn from_scope(scope: &RecoveryScopeV1) -> Self {
        Self {
            authority_domain: scope.authority_domain.clone(),
            tenant_id: scope.tenant_id.clone(),
        }
    }

    pub(in crate::admission_operation_store) fn scope_key(
        &self,
    ) -> Result<String, AdmissionOperationStoreError> {
        Ok(sha256_hex(&protected::encode(self)?))
    }

    pub(in crate::admission_operation_store) fn ready_key(
        &self,
    ) -> Result<String, AdmissionOperationStoreError> {
        Ok(format!("knowledge-reference-ready:{}", self.scope_key()?))
    }
}

/// This is descriptive data only. The owning source adapter and closed writer
/// must finish the entire cold census before persisting its first event.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct ReferenceReadyRecord {
    pub(in crate::admission_operation_store) schema: ReferenceReadySchema,
    pub(in crate::admission_operation_store) account: ReferenceAccount,
    pub(in crate::admission_operation_store) cutoff: ReferenceCutoff,
    pub(in crate::admission_operation_store) cohort_digest: CanonicalPayloadDigest,
    pub(in crate::admission_operation_store) census_digest: CanonicalPayloadDigest,
    pub(in crate::admission_operation_store) artifact_count: SafeInteger,
    pub(in crate::admission_operation_store) active_owner_count: SafeInteger,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(in crate::admission_operation_store) enum ReferenceReadySchema {
    #[serde(rename = "chio.knowledge.reference-ready.v1")]
    V1,
    #[serde(rename = "chio.knowledge.reference-ready.v2")]
    V2,
    #[serde(rename = "chio.knowledge.reference-ready.v3")]
    V3,
}

pub(in crate::admission_operation_store) struct ReadyReferenceAccount {
    record: ReferenceReadyRecord,
    source: protected::ProtectedSourceReference,
}

impl ReadyReferenceAccount {
    /// The original input producer is integrated only by this schema. Both
    /// predecessor markers retain their authenticated historical cutoff and
    /// conservative source barriers; they cannot assert complete coverage.
    pub(in crate::admission_operation_store) fn has_complete_writer_coverage(&self) -> bool {
        self.record.schema == ReferenceReadySchema::V3
    }

    pub(in crate::admission_operation_store) fn cutoff(&self) -> &ReferenceCutoff {
        &self.record.cutoff
    }

    pub(in crate::admission_operation_store) fn cohort_digest(&self) -> &CanonicalPayloadDigest {
        &self.record.cohort_digest
    }

    pub(in crate::admission_operation_store) fn census_digest(&self) -> &CanonicalPayloadDigest {
        &self.record.census_digest
    }

    pub(in crate::admission_operation_store) fn artifact_count(&self) -> u64 {
        self.record.artifact_count.get()
    }

    pub(in crate::admission_operation_store) fn active_owner_count(&self) -> u64 {
        self.record.active_owner_count.get()
    }

    pub(in crate::admission_operation_store) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.source
    }

    pub(in crate::admission_operation_store) fn verify_current(
        &self,
        tx: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        protected::verify_source_reference(tx, &self.source)?;
        self.record.cutoff.verify(tx)
    }
}

/// Missing or historical-only readiness refuses. Counts are the immutable
/// activation census, not current live-owner counters or a zero-custody proof.
pub(in crate::admission_operation_store) fn ready_reference_account(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<ReadyReferenceAccount, AdmissionOperationStoreError> {
    let account = ReferenceAccount::from_scope(scope);
    let key = account.ready_key()?;
    let row = protected::raw_checked(tx, &key)?
        .ok_or_else(|| refused("reference account is not initialized"))?;
    let source = protected::source_reference(tx, &key)?;
    let record: ReferenceReadyRecord = protected::decode(&row.payload)?;
    let header_is_local: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM admission_operation_recovery_records WHERE record_key=?1",
            [&key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if record.account != account
        || row.kind != "command"
        || row.scope != account.scope_key()?
        || row.version != 1
        || source.version() != 1
        || source.scope_key() != row.scope
        || source.kind() != "command"
        || !header_is_local
        || source.global_commit_sequence() <= record.cutoff.sequence()
    {
        return Err(refused("reference account activation identity changed"));
    }
    record.cutoff.verify(tx)?;
    if !protected::matches_historical_command_payload(
        tx,
        &key,
        &row.scope,
        1,
        &protected::encode(&record)?,
    )? {
        return Err(refused(
            "reference account activation changed its first census",
        ));
    }
    Ok(ReadyReferenceAccount { record, source })
}

impl std::fmt::Debug for ReadyReferenceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadyReferenceAccount([redacted])")
    }
}
