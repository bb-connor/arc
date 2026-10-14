//! Standalone manifests retained before manifests had owners are recorded once
//! as a closed baseline. Every later manifest must be cited by a publication.
use super::*;
use std::collections::HashSet;

const BASELINE_KEY_PREFIX: &str = "knowledge-import-baseline:";

/// Rows whose first retained event is at or below `event_ceiling` are the
/// baseline; `count` and `digest` pin their exact keys and payload bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportManifestBaselineV1 {
    domain_version: VersionV1,
    count: SafeInteger,
    digest: String,
    event_ceiling: SafeInteger,
}

/// The record a baseline installation hands the settlement-band sink. It is
/// bound to the writer that censused the rows and rechecks them at the sink.
pub(in crate::admission_operation_store) struct VerifiedImportManifestBaseline<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    key: String,
    scope_key: String,
    payload: Vec<u8>,
}
impl<'conn> VerifiedImportManifestBaseline<'_, 'conn> {
    /// Same writer, this owner's key and scope, a canonical bounded payload whose
    /// event ceiling is the current head, and the fresh census count and digest.
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
        owner: &SqliteServingOwner,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(
            std::ops::Deref::deref(self.transaction),
            std::ops::Deref::deref(tx),
        ) {
            return Err(refused(
                "import manifest baseline changed its physical writer",
            ));
        }
        if self.key != baseline_key(owner) || self.scope_key != baseline_scope(owner)? {
            return Err(refused("import manifest baseline changed its owner"));
        }
        // decode refuses an empty, oversized or non-canonical payload.
        let baseline: ImportManifestBaselineV1 = protected::decode(&self.payload)?;
        let rows = census(tx)?;
        if baseline.event_ceiling.get() != event_head(tx)?
            || u64::try_from(rows.len()).map_err(refused)? != baseline.count.get()
            || census_digest(rows.iter()) != baseline.digest
        {
            return Err(refused("import manifest baseline lost its census"));
        }
        Ok(())
    }
    pub(in crate::admission_operation_store) fn key(&self) -> &str {
        &self.key
    }
    pub(in crate::admission_operation_store) fn scope_key(&self) -> &str {
        &self.scope_key
    }
    pub(in crate::admission_operation_store) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

struct RetainedManifest {
    key: String,
    scope: String,
    digest: String,
    payload_sha256: String,
    first_event: u64,
}

fn startup_error(error: AdmissionOperationStoreError) -> crate::SqliteServingOwnerError {
    crate::SqliteServingOwnerError::Invalid(error.to_string())
}

fn baseline_key(owner: &SqliteServingOwner) -> String {
    format!(
        "{BASELINE_KEY_PREFIX}{}",
        sha256_hex(owner.fence.store_uuid.as_bytes())
    )
}

fn baseline_scope(owner: &SqliteServingOwner) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&protected::encode(&(
        "knowledge-import-manifest-baseline-v1",
        &owner.fence.store_uuid,
    ))?))
}

fn census(tx: &Connection) -> Result<Vec<RetainedManifest>, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-import:*'
             UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'knowledge-import:*'
             UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'knowledge-import:*'
             ORDER BY 1",
        )
        .map_err(sqlite_error)?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let mut rows = Vec::with_capacity(keys.len());
    for key in keys {
        let raw = protected::raw_checked(tx, &key)?
            .ok_or_else(|| refused("import manifest census source disappeared"))?;
        let (scope, digest) = key
            .strip_prefix(MANIFEST_PREFIX)
            .and_then(|rest| rest.split_once(':'))
            .ok_or_else(|| refused("import manifest census key"))?;
        let manifest: SignedArtifactArchiveManifestV1 = protected::decode(&raw.payload)?;
        let first_event: i64 = tx
            .query_row(
                "SELECT MIN(sequence) FROM admission_operation_recovery_events WHERE record_key=?1",
                [&key],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if raw.kind != "command"
            || raw.version != 1
            || raw.scope != scope
            || hex::encode(
                artifact_archive_digest(manifest.body())
                    .map_err(refused)?
                    .as_bytes(),
            ) != digest
        {
            return Err(refused("import manifest census changed its original row"));
        }
        rows.push(RetainedManifest {
            scope: scope.to_owned(),
            digest: digest.to_owned(),
            payload_sha256: sha256_hex(&raw.payload),
            first_event: u64::try_from(first_event).map_err(refused)?,
            key,
        });
    }
    Ok(rows)
}

fn census_digest<'a>(rows: impl Iterator<Item = &'a RetainedManifest>) -> String {
    rows.fold(
        sha256_hex(b"knowledge-import-manifest-baseline-v1"),
        |chain, row| sha256_hex(format!("{chain}:{}:{}", row.key, row.payload_sha256).as_bytes()),
    )
}

fn event_head(tx: &Connection) -> Result<u64, AdmissionOperationStoreError> {
    let head: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(sequence),0) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    u64::try_from(head).map_err(refused)
}

fn write_baseline<'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    rows: &[RetainedManifest],
) -> Result<(), AdmissionOperationStoreError> {
    let baseline = ImportManifestBaselineV1 {
        domain_version: VersionV1,
        count: SafeInteger::new(u64::try_from(rows.len()).map_err(refused)?).map_err(refused)?,
        digest: census_digest(rows.iter()),
        event_ceiling: SafeInteger::new(event_head(tx)?).map_err(refused)?,
    };
    protected::persist_knowledge_import_baseline(
        tx,
        owner,
        VerifiedImportManifestBaseline {
            transaction: tx,
            key: baseline_key(owner),
            scope_key: baseline_scope(owner)?,
            payload: protected::encode(&baseline)?,
        },
    )
}

/// A new manifest is retained only after startup recorded the baseline of
/// standalone rows, so every row of that baseline predates ownership.
pub(super) fn require_authority_baseline(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
) -> Result<(), AdmissionOperationStoreError> {
    protected::raw_checked(tx, &baseline_key(owner))?
        .map(|_| ())
        .ok_or_else(|| refused("import manifest baseline absent"))
}

fn cited_manifests(
    tx: &Connection,
) -> Result<HashSet<(String, String)>, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'",
        )
        .map_err(sqlite_error)?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let mut cited = HashSet::new();
    for key in keys {
        let raw = protected::raw_checked(tx, &key)?
            .ok_or_else(|| refused("publication source disappeared"))?;
        let record: NativeArtifactRecordV1 = protected::decode(&raw.payload)?;
        if let ArtifactProducerV1::Import { manifest, .. } = &record.input.producer {
            cited.insert((raw.scope, hex::encode(manifest.as_bytes())));
        }
    }
    Ok(cited)
}

fn verify_baseline(
    tx: &Connection,
    owner: &SqliteServingOwner,
    raw: protected::RawRecord,
) -> Result<(), AdmissionOperationStoreError> {
    let key = baseline_key(owner);
    let scope = baseline_scope(owner)?;
    let source = protected::source_reference(tx, &key)?;
    let baseline: ImportManifestBaselineV1 = protected::decode(&raw.payload)?;
    if raw.version != 1
        || raw.kind != "command"
        || raw.scope != scope
        || source.version() != 1
        || source.kind() != "command"
        || source.scope_key() != scope
    {
        return Err(refused("import manifest baseline changed its original row"));
    }
    let (original, later): (Vec<_>, Vec<_>) = census(tx)?
        .into_iter()
        .partition(|row| row.first_event <= baseline.event_ceiling.get());
    if u64::try_from(original.len()).map_err(refused)? != baseline.count.get()
        || census_digest(original.iter()) != baseline.digest
    {
        return Err(refused("import manifest baseline history changed"));
    }
    if later.is_empty() {
        return Ok(());
    }
    let cited = cited_manifests(tx)?;
    if later
        .iter()
        .all(|row| cited.contains(&(row.scope.clone(), row.digest.clone())))
    {
        return Ok(());
    }
    Err(refused("import manifest has no citing publication"))
}

fn settle(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
) -> Result<usize, AdmissionOperationStoreError> {
    let present: bool = tx
        .query_row(
            "SELECT COUNT(*) = 3 FROM sqlite_schema
             WHERE name IN ('admission_operation_recovery_records',
                            'admission_operation_recovery_events',
                            'authority_global_commits')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !present {
        return Ok(0);
    }
    if let Some(raw) = protected::raw_checked(tx, &baseline_key(owner))? {
        verify_baseline(tx, owner, raw)?;
        return Ok(0);
    }
    write_baseline(tx, owner, &census(tx)?)?;
    Ok(1)
}

/// Opens the authority's manifest history under its owner: records the baseline
/// of standalone manifests once, even when there are none, and refuses an
/// authority whose baseline rows changed or whose later manifests lack a
/// citing publication.
pub(crate) fn publish_import_manifest_baseline_at_startup(
    connection: &mut Connection,
    owner: &SqliteServingOwner,
) -> Result<usize, crate::SqliteServingOwnerError> {
    #[cfg(any(test, feature = "admission-test-support"))]
    if prior_format_startup() {
        return Ok(0);
    }
    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(crate::SqliteServingOwnerError::from)?;
    crate::admission_operation_store::schema::verify_active_owner(&tx, owner, Some(&owner.fence))
        .map_err(startup_error)?;
    owner.verify_authority_anchor(&tx)?;
    let published = settle(&tx, owner).map_err(startup_error)?;
    tx.commit().map_err(|error| {
        owner.outcome_unknown(format!(
            "import manifest baseline commit outcome unknown: {error}"
        ))
    })?;
    if published != 0 {
        owner.sync_authority_anchor(connection)?;
    }
    Ok(published)
}

#[cfg(any(test, feature = "admission-test-support"))]
thread_local! {
    static PRIOR_FORMAT_STARTUP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// While held, stores opened on this thread skip the manifest baseline exactly
/// as a prior-44 binary did.
#[cfg(any(test, feature = "admission-test-support"))]
pub struct PriorFormatImportStartupGuard(());

#[cfg(any(test, feature = "admission-test-support"))]
impl PriorFormatImportStartupGuard {
    pub fn arm() -> Self {
        PRIOR_FORMAT_STARTUP.with(|prior| prior.set(true));
        Self(())
    }
}

#[cfg(any(test, feature = "admission-test-support"))]
impl Drop for PriorFormatImportStartupGuard {
    fn drop(&mut self) {
        PRIOR_FORMAT_STARTUP.with(|prior| prior.set(false));
    }
}

#[cfg(any(test, feature = "admission-test-support"))]
fn prior_format_startup() -> bool {
    PRIOR_FORMAT_STARTUP.with(std::cell::Cell::get)
}
