//! Exact immutable native observation backing an original private release.
use super::*;

/// Data only. The surrounding owner has already anchored the native reader or
/// writer. This lookup never authorizes delivery or replaces current admission.
pub(in crate::admission_operation_store) fn release_observation_source(
    tx: &Connection,
    intent: &ArtifactReleaseIntentV1,
) -> Result<protected::ProtectedSourceReference, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-join:*'
               AND json_extract(payload,'$.release.release')=?1
             ORDER BY record_key LIMIT 2",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query([intent.release.as_str()])
        .map_err(sqlite_error)?;
    let key: String = rows
        .next()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("release lost its native observation"))?
        .get(0)
        .map_err(sqlite_error)?;
    if rows.next().map_err(sqlite_error)?.is_some() {
        return Err(invalid("release has ambiguous native observations"));
    }
    let row = protected::raw_checked(tx, &key)?
        .ok_or_else(|| invalid("release native observation disappeared"))?;
    let decoded = encoding::decode(tx, &key, row.version, &row.payload)?;
    if key != record_key(&decoded.authority, decoded.sequence) {
        return Err(invalid("release native observation changed its key"));
    }
    let (record, _) = load_with_digest(tx, &decoded.authority, decoded.sequence)?;
    let mut admitted = intent.clone();
    admitted.state = chio_security_types::knowledge::ArtifactDeliveryStateV1::Admitted;
    if record.release != admitted || record.scope != intent.artifact.scope {
        return Err(invalid(
            "release native observation changed its exact intent",
        ));
    }
    protected::source_reference(tx, &key)
}
