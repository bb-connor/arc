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
/// create the account before any installation or artifact can use it.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct ReferenceReadyRecord {
    pub(in crate::admission_operation_store) schema: ReferenceReadySchema,
    pub(in crate::admission_operation_store) account: ReferenceAccount,
    pub(in crate::admission_operation_store) cutoff: ReferenceCutoff,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(in crate::admission_operation_store) enum ReferenceReadySchema {
    #[serde(rename = "chio.knowledge.reference-ready.v3")]
    V3,
}

pub(in crate::admission_operation_store) struct ReadyReferenceAccount {
    record: ReferenceReadyRecord,
    source: protected::ProtectedSourceReference,
}

impl ReadyReferenceAccount {
    pub(in crate::admission_operation_store) fn cutoff(&self) -> &ReferenceCutoff {
        &self.record.cutoff
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

/// Missing or historical-only readiness refuses; it never means zero custody.
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
            "reference account activation changed its original initialization",
        ));
    }
    Ok(ReadyReferenceAccount { record, source })
}

impl std::fmt::Debug for ReadyReferenceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadyReferenceAccount([redacted])")
    }
}
