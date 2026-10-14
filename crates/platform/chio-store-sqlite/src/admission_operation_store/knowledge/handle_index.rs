//! One append-only handle index per original artifact version.
//!
//! The index lists the generated identity of every handle issued for its
//! version across all principals, recipients and profile generations. The
//! immutable handle row binds the rest. One authority-wide baseline, written
//! once by the startup migration, fixes the global cut: a handle is legacy only
//! when its original commit is at or before that cut and its version's census
//! binds it by count and set digest.
use super::release::{handle_key, HandleRecord};
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[cfg(any(test, feature = "admission-test-support"))]
mod legacy_fixture;
#[cfg(any(test, feature = "admission-test-support"))]
pub use legacy_fixture::PriorFormatHandleStartupGuard;
#[cfg(test)]
mod tests;

/// One canonical entry is at least its quoted 64-hex identity.
const MIN_ENTRY_BYTES: usize = 66;
/// No canonical index within the record bound can hold more entries. The
/// actual canonical size is still checked before every write.
const MAX_HANDLE_INDEX_ENTRIES: usize =
    chio_kernel::recovery::MAX_RECOVERY_RECORD_BYTES / MIN_ENTRY_BYTES;
const MAX_BASELINE_BYTES: usize = 1024;
const CENSUS_DOMAIN: &[u8] = b"chio.knowledge.handle-census.v1";
const BASELINE_DOMAIN: &[u8] = b"chio.knowledge.handle-baseline.v1";
const INDEX_PREFIX: &str = "knowledge-handle-index:";
const BASELINE_PREFIX: &str = "knowledge-handle-baseline:";

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyHandleCensus {
    count: SafeInteger,
    digest: String,
    cut: SafeInteger,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandleIndexV1 {
    artifact: ArtifactVersionRefV1,
    legacy: Option<LegacyHandleCensus>,
    entries: BoundedList<ArtifactHandleId, MAX_HANDLE_INDEX_ENTRIES>,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
enum HandleBaselineSchema {
    #[serde(rename = "chio.knowledge.handle-baseline.v1")]
    V1,
}

/// The one migration baseline of an authority. Its own immutable global commit
/// follows exactly the census indices written after `cut` in its transaction.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandleBaselineV1 {
    schema: HandleBaselineSchema,
    authority: String,
    cut: SafeInteger,
    versions: SafeInteger,
    handles: SafeInteger,
    digest: String,
}

pub(super) fn index_key(
    reference: &ArtifactVersionRefV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "{INDEX_PREFIX}{}:{}",
        scope_key(&reference.scope)?,
        sha256_hex(&protected::encode(reference)?)
    ))
}

pub(super) fn baseline_key(authority: &str) -> String {
    format!("{BASELINE_PREFIX}{}", sha256_hex(authority.as_bytes()))
}

fn baseline_scope(authority: &str) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&protected::encode(&(
        "knowledge-handle-baseline-v1",
        authority,
    ))?))
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

impl HandleIndexV1 {
    fn validate(
        &self,
        reference: &ArtifactVersionRefV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut entries = BTreeSet::new();
        let closed = match &self.legacy {
            Some(census) => census.count.get() != 0 && is_hex_digest(&census.digest),
            None => !self.entries.as_slice().is_empty(),
        };
        if !closed
            || self.artifact != *reference
            || !self
                .entries
                .as_slice()
                .iter()
                .all(|handle| is_hex_digest(handle.as_str()) && entries.insert(handle))
        {
            return Err(refused("handle index changed its closed entries"));
        }
        Ok(())
    }
}

/// The authenticated baseline of one authority and its own global commit.
fn current_baseline(
    tx: &Connection,
    authority: &str,
) -> Result<Option<(HandleBaselineV1, u64)>, AdmissionOperationStoreError> {
    let key = baseline_key(authority);
    let Some(row) = protected::raw_checked(tx, &key)? else {
        return Ok(None);
    };
    let source = protected::source_reference(tx, &key)?;
    let baseline: HandleBaselineV1 = protected::decode(&row.payload)?;
    let commit = baseline
        .cut
        .get()
        .checked_add(baseline.versions.get())
        .and_then(|commit| commit.checked_add(1));
    if row.kind != "command"
        || row.scope != baseline_scope(authority)?
        || row.payload.len() > MAX_BASELINE_BYTES
        || source.version() != 1
        || baseline.authority != authority
        || !is_hex_digest(&baseline.digest)
        || baseline.versions.get() > baseline.handles.get()
        || commit != Some(source.global_commit_sequence())
    {
        return Err(refused("handle baseline changed its migration position"));
    }
    Ok(Some((baseline, source.global_commit_sequence())))
}

/// The current index of one version and its exact head, or the empty typed
/// index of a version without a handle. The baseline must already exist.
pub(super) struct CurrentHandleIndex {
    index: HandleIndexV1,
    cut: u64,
    source: Option<protected::ProtectedSourceReference>,
}

pub(super) fn current(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<CurrentHandleIndex, AdmissionOperationStoreError> {
    let (baseline, _) = current_baseline(tx, reference.scope.authority_domain.as_str())?
        .ok_or_else(|| refused("handle baseline absent"))?;
    let cut = baseline.cut.get();
    let key = index_key(reference)?;
    let Some(row) = protected::raw_checked(tx, &key)? else {
        return Ok(CurrentHandleIndex {
            index: HandleIndexV1 {
                artifact: reference.clone(),
                legacy: None,
                entries: BoundedList::new(Vec::new()).map_err(refused)?,
            },
            cut,
            source: None,
        });
    };
    let index: HandleIndexV1 = protected::decode(&row.payload)?;
    index.validate(reference)?;
    if row.kind != "command"
        || row.scope != scope_key(&reference.scope)?
        || index
            .legacy
            .as_ref()
            .is_some_and(|census| census.cut.get() != cut)
    {
        return Err(refused("handle index changed its owner"));
    }
    Ok(CurrentHandleIndex {
        index,
        cut,
        source: Some(protected::source_reference(tx, &key)?),
    })
}

impl CurrentHandleIndex {
    /// An existing handle row of this version is admitted when listed, or when
    /// its original commit is within the baseline census of its version.
    pub(super) fn admits(
        &self,
        tx: &Connection,
        record: &HandleRecord,
    ) -> Result<bool, AdmissionOperationStoreError> {
        if record.artifact != self.index.artifact {
            return Ok(false);
        }
        if self
            .index
            .entries
            .as_slice()
            .contains(&record.handle.handle)
        {
            return Ok(true);
        }
        if self.index.legacy.is_none() {
            return Ok(false);
        }
        let source = protected::source_reference(
            tx,
            &handle_key(&record.artifact.scope, &record.handle.handle)?,
        )?;
        Ok(source.version() == 1 && source.global_commit_sequence() <= self.cut)
    }

    /// The canonical index with one more identity. Legacy rows count toward
    /// the same per-version bound, so an overfull census admits no alias.
    pub(super) fn appended(
        &self,
        handle: &ArtifactHandleId,
    ) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let mut entries = self.index.entries.as_slice().to_vec();
        if !is_hex_digest(handle.as_str()) || entries.contains(handle) {
            return Err(refused("handle index entry"));
        }
        entries.push(handle.clone());
        let legacy = self
            .index
            .legacy
            .as_ref()
            .map_or(0, |census| census.count.get());
        let total = usize::try_from(legacy)
            .ok()
            .and_then(|legacy| legacy.checked_add(entries.len()));
        if total.is_none_or(|total| total > MAX_HANDLE_INDEX_ENTRIES) {
            return Err(refused("handle index exhausted"));
        }
        let index = HandleIndexV1 {
            artifact: self.index.artifact.clone(),
            legacy: self.index.legacy.clone(),
            entries: BoundedList::new(entries).map_err(|_| refused("handle index exhausted"))?,
        };
        protected::encode(&index).map_err(|_| refused("handle index exhausted"))
    }

    pub(super) fn into_source(self) -> Option<protected::ProtectedSourceReference> {
        self.source
    }
}

/// One record of the startup migration: a census index of a supported
/// prior-44 version, or the authority baseline after them. Only the migration
/// builds it, from the authenticated rows it streamed in this transaction.
pub(in crate::admission_operation_store) struct VerifiedHandleCensus {
    key: String,
    scope_key: String,
    payload: Vec<u8>,
}

impl VerifiedHandleCensus {
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

fn startup_error(error: AdmissionOperationStoreError) -> crate::SqliteServingOwnerError {
    crate::SqliteServingOwnerError::Invalid(error.to_string())
}

/// Install the authority baseline once, with the census index of every
/// version whose handles predate it, then verify every handle and index
/// against that baseline. One immediate transaction under the current owner
/// and anchor; any failure rolls back every write and refuses open.
pub(crate) fn census_handle_indices_at_startup(
    connection: &mut Connection,
    owner: &SqliteServingOwner,
) -> Result<usize, crate::SqliteServingOwnerError> {
    #[cfg(any(test, feature = "admission-test-support"))]
    if legacy_fixture::prior_format_startup() {
        return Ok(0);
    }
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(crate::SqliteServingOwnerError::from)?;
    schema::verify_active_owner(&tx, owner, Some(&owner.fence)).map_err(startup_error)?;
    owner.verify_authority_anchor(&tx)?;
    let installed = migrate(&tx, owner).map_err(startup_error)?;
    verify(&tx, &owner.fence.store_uuid).map_err(startup_error)?;
    tx.commit().map_err(|error| {
        owner.outcome_unknown(format!(
            "handle index migration commit outcome unknown: {error}"
        ))
    })?;
    if installed != 0 {
        owner.sync_authority_anchor(connection)?;
    }
    Ok(installed)
}

fn present(tx: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema
         WHERE name='admission_operation_recovery_records')",
        [],
        |row| row.get(0),
    )
    .map_err(sqlite_error)
}

/// The one-time migration. It runs only when the authority has no baseline,
/// no baseline history and no index row, and writes its census indices and
/// then the baseline even for an empty inventory.
fn migrate(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
) -> Result<usize, AdmissionOperationStoreError> {
    if !present(tx)? {
        return Ok(0);
    }
    let authority = owner.fence.store_uuid.as_str();
    if current_baseline(tx, authority)?.is_some() {
        return Ok(0);
    }
    let indexed: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM main.admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-handle-index:*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if indexed {
        return Err(refused("handle index exists without its baseline"));
    }
    let head: i64 = tx
        .query_row(
            "SELECT head_sequence FROM main.authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let cut = u64::try_from(head).map_err(|_| refused("handle baseline global head"))?;
    let mut installed = 0;
    for_each_version(tx, cut, |version| {
        if !version.listed.is_empty() {
            return Err(refused("handle census row follows its cut"));
        }
        retained_version(tx, &version.artifact)?;
        let index = HandleIndexV1 {
            legacy: Some(LegacyHandleCensus {
                count: SafeInteger::new(version.legacy).map_err(refused)?,
                digest: version.digest,
                cut: SafeInteger::new(cut).map_err(refused)?,
            }),
            entries: BoundedList::new(Vec::new()).map_err(refused)?,
            artifact: version.artifact,
        };
        index.validate(&index.artifact)?;
        protected::persist_knowledge_handle_census(
            tx,
            owner,
            VerifiedHandleCensus {
                key: index_key(&index.artifact)?,
                scope_key: scope_key(&index.artifact.scope)?,
                payload: protected::encode(&index)?,
            },
        )?;
        installed += 1;
        Ok(())
    })?;
    let summary = census_summary(tx, cut)?;
    let baseline = HandleBaselineV1 {
        schema: HandleBaselineSchema::V1,
        authority: authority.to_owned(),
        cut: SafeInteger::new(cut).map_err(refused)?,
        versions: SafeInteger::new(summary.versions).map_err(refused)?,
        handles: SafeInteger::new(summary.handles).map_err(refused)?,
        digest: summary.digest,
    };
    protected::persist_knowledge_handle_census(
        tx,
        owner,
        VerifiedHandleCensus {
            key: baseline_key(authority),
            scope_key: baseline_scope(authority)?,
            payload: protected::encode(&baseline)?,
        },
    )?;
    Ok(installed + 1)
}

/// Cold verification of every handle and index against the one baseline.
fn verify(tx: &Connection, authority: &str) -> Result<(), AdmissionOperationStoreError> {
    if !present(tx)? {
        return Ok(());
    }
    let (baseline, written) =
        current_baseline(tx, authority)?.ok_or_else(|| refused("handle baseline absent"))?;
    let cut = baseline.cut.get();
    for_each_version(tx, cut, |version| {
        let index = current(tx, &version.artifact)?;
        if index.source.is_none() {
            return Err(refused("handle row has no version index"));
        }
        let unchanged = match &index.index.legacy {
            Some(census) => census.count.get() == version.legacy && census.digest == version.digest,
            None => version.legacy == 0,
        };
        if !unchanged || version.unlisted(&index.index) {
            return Err(refused("handle row is not bound by its version index"));
        }
        Ok(())
    })?;
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-handle-index:*' ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let (index, created) = index_row(tx, &key)?;
        retained_version(tx, &index.artifact)?;
        let placed = match &index.legacy {
            Some(census) => census.cut.get() == cut && created > cut && created < written,
            None => created > written,
        };
        if !placed {
            return Err(refused("handle index changed its migration position"));
        }
        for handle in index.entries.as_slice() {
            let (record, source) = handle_row(tx, &handle_key(&index.artifact.scope, handle)?)?;
            if record.artifact != index.artifact || source.global_commit_sequence() <= cut {
                return Err(refused("handle index entry lost its row"));
            }
        }
    }
    let summary = census_summary(tx, cut)?;
    if summary.versions != baseline.versions.get()
        || summary.handles != baseline.handles.get()
        || summary.digest != baseline.digest
    {
        return Err(refused("handle baseline changed its census"));
    }
    Ok(())
}

/// One authenticated index row and its original global commit.
fn index_row(
    tx: &Connection,
    key: &str,
) -> Result<(HandleIndexV1, u64), AdmissionOperationStoreError> {
    let row = protected::raw_checked(tx, key)?.ok_or_else(|| refused("handle index row absent"))?;
    let index: HandleIndexV1 = protected::decode(&row.payload)?;
    index.validate(&index.artifact)?;
    if row.kind != "command"
        || row.scope != scope_key(&index.artifact.scope)?
        || index_key(&index.artifact)? != key
    {
        return Err(refused("handle index changed its owner"));
    }
    Ok((index, protected::historical_record_commit(tx, key, 1)?))
}

struct CensusSummary {
    versions: u64,
    handles: u64,
    digest: String,
}

/// The baseline digest over every census index in key order.
fn census_summary(
    tx: &Connection,
    cut: u64,
) -> Result<CensusSummary, AdmissionOperationStoreError> {
    let mut digest = Sha256::new();
    digest.update(BASELINE_DOMAIN);
    let (mut versions, mut handles) = (0_u64, 0_u64);
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-handle-index:*' ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let (index, _) = index_row(tx, &key)?;
        let Some(census) = index.legacy else {
            continue;
        };
        if census.cut.get() != cut {
            return Err(refused("handle census changed its cut"));
        }
        digest.update(protected::encode(&(&key, census.count, &census.digest))?);
        versions = versions
            .checked_add(1)
            .ok_or_else(|| refused("handle baseline version count"))?;
        handles = handles
            .checked_add(census.count.get())
            .ok_or_else(|| refused("handle baseline handle count"))?;
    }
    Ok(CensusSummary {
        versions,
        handles,
        digest: hex::encode(digest.finalize()),
    })
}

/// One authenticated, immutable handle row bound to its own key.
fn handle_row(
    tx: &Connection,
    key: &str,
) -> Result<(HandleRecord, protected::ProtectedSourceReference), AdmissionOperationStoreError> {
    let row = protected::raw_checked(tx, key)?.ok_or_else(|| refused("handle row absent"))?;
    let record: HandleRecord = protected::decode(&row.payload)?;
    let source = protected::source_reference(tx, key)?;
    if row.kind != "command"
        || source.version() != 1
        || row.scope != scope_key(&record.artifact.scope)?
        || handle_key(&record.artifact.scope, &record.handle.handle)? != key
        || !is_hex_digest(record.handle.handle.as_str())
        || record.handle.recipient != record.recipient.recipient
    {
        return Err(refused("handle row changed its original binding"));
    }
    Ok((record, source))
}

/// Any retained publication state, including collected history. The census
/// reads versions whose live obligation may already have ended.
fn retained_version(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<(), AdmissionOperationStoreError> {
    let key: String =
        load(tx, &version_key(reference)?)?.ok_or_else(|| refused("handle version unknown"))?;
    let record: NativeArtifactRecordV1 =
        load(tx, &key)?.ok_or_else(|| refused("handle publication unknown"))?;
    if record_publication_key(&record)? != key
        || artifact_version_reference(&record.metadata).map_err(refused)? != *reference
    {
        return Err(refused("handle version changed its publication"));
    }
    Ok(())
}

/// The handle rows of one version: the count and key-ordered set digest of
/// rows at or before the cut, and the later rows its index must list.
struct VersionRows {
    artifact: ArtifactVersionRefV1,
    legacy: u64,
    digest: String,
    listed: Vec<ArtifactHandleId>,
}

impl VersionRows {
    fn unlisted(&self, index: &HandleIndexV1) -> bool {
        !self
            .listed
            .iter()
            .all(|handle| index.entries.as_slice().contains(handle))
    }
}

/// Stream handle rows grouped by version with bounded memory: rows at or
/// before the cut are hashed, and later rows are kept only up to the largest
/// listable index. The expression sort materializes every matched row before
/// the first step, and no census write matches its pattern.
fn for_each_version(
    tx: &Connection,
    cut: u64,
    mut visit: impl FnMut(VersionRows) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-handle:*'
             ORDER BY json_extract(CAST(payload AS TEXT),'$.artifact'),record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut group: Option<(VersionRows, Sha256)> = None;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let (record, source) = handle_row(tx, &key)?;
        if group
            .as_ref()
            .is_none_or(|(version, _)| version.artifact != record.artifact)
        {
            if let Some(done) = group.take() {
                visit(finished(done))?;
            }
            let mut digest = Sha256::new();
            digest.update(CENSUS_DOMAIN);
            group = Some((
                VersionRows {
                    artifact: record.artifact.clone(),
                    legacy: 0,
                    digest: String::new(),
                    listed: Vec::new(),
                },
                digest,
            ));
        }
        let (version, digest) = group
            .as_mut()
            .ok_or_else(|| refused("handle census lost its version"))?;
        if source.global_commit_sequence() <= cut {
            digest.update(record.handle.handle.as_str().as_bytes());
            version.legacy = version
                .legacy
                .checked_add(1)
                .ok_or_else(|| refused("handle census count"))?;
        } else {
            if version.listed.len() >= MAX_HANDLE_INDEX_ENTRIES {
                return Err(refused("handle rows exceed their version index"));
            }
            version.listed.push(record.handle.handle);
        }
    }
    if let Some(done) = group.take() {
        visit(finished(done))?;
    }
    Ok(())
}

fn finished((mut version, digest): (VersionRows, Sha256)) -> VersionRows {
    version.digest = hex::encode(digest.finalize());
    version
}
