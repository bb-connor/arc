//! The single protected root record of one authority's imported scope index.
use super::model::IndexRoot;
use super::*;
use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};

/// Bounds the decoded record: native binding, two digests, a hash and a count.
const MAX_ROOT_PAYLOAD_BYTES: usize = 4 * 1024;

pub(super) const ROOT_KEY_PREFIX: &str = "knowledge-imported-influence-root:";

pub(super) fn record_key(authority: &str) -> String {
    format!("{ROOT_KEY_PREFIX}{}", sha256_hex(authority.as_bytes()))
}

/// The protected scope names this store and native authority under its own
/// domain tag, so the root can never be mistaken for a native slot.
fn protected_scope(
    binding: &NativeSecurityAuthorityBindingV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(hex::encode(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeInfluenceScope,
            &(
                "imported-influence-scope-index-root-v1",
                binding.store_uuid().as_str(),
                binding,
            ),
        )
        .map_err(invalid)?,
    ))
}

/// The single root of one authority's imported scope index, minted only by
/// the hydration writer that installs the index, at its absent key.
pub(in crate::admission_operation_store) struct VerifiedImportedInfluenceRoot<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    authority: String,
    key: String,
    scope: String,
    payload: Vec<u8>,
}

impl<'conn> VerifiedImportedInfluenceRoot<'_, 'conn> {
    pub(in crate::admission_operation_store) fn key(&self) -> &str {
        &self.key
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &str {
        &self.scope
    }
    pub(in crate::admission_operation_store) fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Same writer; the exact key and scope of its authority; a bounded
    /// payload; and an absent key, so a root is never rewritten.
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(
            std::ops::Deref::deref(self.transaction),
            std::ops::Deref::deref(tx),
        ) || self.key != record_key(&self.authority)
            || self.payload.is_empty()
            || self.payload.len() > MAX_ROOT_PAYLOAD_BYTES
            || protected::raw_checked(tx, &self.key)?.is_some()
        {
            return Err(invalid(
                "imported scope index root changed its writer or custody",
            ));
        }
        Ok(())
    }
}

pub(super) fn save_root(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    binding: &NativeSecurityAuthorityBindingV1,
    root: &IndexRoot,
) -> Result<(), AdmissionOperationStoreError> {
    let authority = binding.security_authority_id().as_str();
    let proof = VerifiedImportedInfluenceRoot {
        transaction: tx,
        authority: authority.to_owned(),
        key: record_key(authority),
        scope: protected_scope(binding)?,
        payload: protected::encode(root)?,
    };
    protected::persist_imported_influence_root(tx, owner, &proof)
}

/// Load and authenticate the protected root against the current initialization.
/// A missing, rewritten, re-framed or stale root refuses; there is no fallback
/// reader for a hydrated authority.
pub(in crate::admission_operation_store) fn authenticate_root(
    connection: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<IndexRoot, AdmissionOperationStoreError> {
    let key = record_key(binding.security_authority_id().as_str());
    let scope = protected_scope(binding)?;
    let row = protected::raw_checked(connection, &key)?
        .ok_or_else(|| invalid("imported scope index root is absent"))?;
    let source = protected::source_reference(connection, &key)?;
    let ordinary: bool = connection
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM admission_operation_recovery_records WHERE record_key=?1",
            [&key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if row.version != 1
        || source.version() != 1
        || row.kind != "command"
        || source.kind() != "command"
        || row.scope != scope
        || source.scope_key() != scope
        || row.payload.len() > MAX_ROOT_PAYLOAD_BYTES
        || !ordinary
    {
        return Err(invalid(
            "imported scope index root changed its protected framing",
        ));
    }
    let root: IndexRoot = protected::decode(&row.payload)?;
    if !root.is_bound_to(binding, initialization) {
        return Err(invalid(
            "imported scope index root changed its exact source",
        ));
    }
    Ok(root)
}

/// Roots held by protected records, bounded by the number of initialized
/// authorities the caller expects, so excess custody is detected without an
/// unbounded read.
pub(super) fn count_roots(
    connection: &Connection,
    limit: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let counted: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM (SELECT 1 FROM admission_operation_recovery_records
             WHERE record_key GLOB ?1 LIMIT ?2)",
            params![
                format!("{ROOT_KEY_PREFIX}*"),
                i64::try_from(limit.saturating_add(1)).map_err(invalid)?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    u64::try_from(counted).map_err(invalid)
}
