//! The original full-scan contribution formula, kept only as the oracle the
//! scoped reader's commitment is compared against.
use super::*;
use crate::security_state::decode_retained_security_row;

/// Scan every retained row of every relevant table in table and row order and
/// commit to the `(table, sha256(bytes))` pair of each row matching this flow.
pub(in crate::admission_operation_store) fn full_scan_commitment(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
    key: &FlowStateKey,
) -> Result<Option<CanonicalPayloadDigest>, AdmissionOperationStoreError> {
    use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};
    let binding = initialization.admission_binding()?;
    let authority = binding.security_authority_id().as_str();
    let mut contributions: Vec<(&'static str, String)> = Vec::new();
    for table in RELEVANT_TABLES {
        let mut statement = connection
            .prepare(
                "SELECT canonical_row FROM security_participant_migration_rows
                 WHERE security_authority_id = ?1 AND table_name = ?2
                 ORDER BY row_index",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![authority, table], |row| row.get::<_, Vec<u8>>(0))
            .map_err(sqlite_error)?;
        for bytes in rows {
            let bytes = bytes.map_err(sqlite_error)?;
            let values = decode_retained_security_row(table, &bytes).map_err(invalid)?;
            if matches_flow(table, &values, key)? {
                contributions.push((table, sha256_hex(&bytes)));
            }
        }
    }
    if contributions.is_empty() {
        return Ok(None);
    }
    Ok(Some(CanonicalPayloadDigest::from_bytes(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeObservedInfluence,
            &(
                &initialization.fingerprint,
                authority,
                binding.store_uuid().as_str(),
                key,
                &contributions,
            ),
        )
        .map_err(invalid)?,
    )))
}
