use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use chio_control_plane::security::{
    validate_active_response_artifacts_draft, validate_active_response_policy_selection,
    ActiveResponseAdmissionArtifactsDraftWire, ActiveResponseAuthorityHandler,
    ActiveResponseAuthorityHandlerError, ActiveResponseAuthorityHandlerResult,
    ActiveResponseAuthorityRejection, ActiveResponsePolicySelectionWire,
};
use chio_core::receipt::security::CorrelatedFindingReceiptBody;
use chio_core::{canonical_json_bytes, PublicKey};
use chio_security_types::ports::{
    AdmissionArtifactRef, AttestedFindingBatchBinding, Digest32, ErrorCode, OpaqueReceiptRef,
    PortError,
};
use chio_security_types::ResponsePlan;
use chio_sqlite_file_identity::main_database_file_identity;
use rusqlite::{params, Connection, OpenFlags};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuthorityError, Result};

pub const AUTHORITY_STORE_BUNDLE_SCHEMA: &str = "chio.active-response-authority.bundle.v1";
pub const AUTHORITY_STORE_MANIFEST_SCHEMA: &str =
    "chio.active-response-authority.store-manifest.v1";
const AUTHORITY_STORE_LOGICAL_DOMAIN: &[u8] = b"chio.active-response-authority.logical-store.v1\0";
const AUTHORITY_SELECTION_KEY_DOMAIN: &str = "chio.active-response-authority.selection-key.v1\0";
const AUTHORITY_ARTIFACT_KEY_DOMAIN: &str = "chio.active-response-authority.artifact-key.v1\0";
const MAX_STORE_RECORDS: usize = 65_536;
const MAX_STORE_PAYLOAD_BYTES: usize = 1_048_576;
const MAX_STORE_FILE_BYTES: u64 = 1_073_741_824;
const AUTHORITY_STORE_APPLICATION_ID: i64 = 0x4348_494f;
const AUTHORITY_STORE_USER_VERSION: i64 = 1;
const AUTHORITY_STORE_SCHEMA_SQL: &str =
    "CREATE TABLE metadata (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL) STRICT;
     CREATE TABLE policies (lookup_key TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL) STRICT;
     CREATE TABLE artifacts (lookup_key TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL) STRICT;";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreAdmittedPolicyRecord {
    pub evidence_id: OpaqueReceiptRef,
    pub finding: CorrelatedFindingReceiptBody,
    pub binding: AttestedFindingBatchBinding,
    pub selection: ActiveResponsePolicySelectionWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreAdmittedArtifactRecord {
    pub response_plan: ResponsePlan,
    pub admission_artifact_ref: AdmissionArtifactRef,
    pub draft: ActiveResponseAdmissionArtifactsDraftWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityStoreBundle {
    pub schema: String,
    pub deployment_digest: Digest32,
    pub authority_identity: PublicKey,
    pub policies: Vec<PreAdmittedPolicyRecord>,
    pub artifacts: Vec<PreAdmittedArtifactRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityStoreManifest {
    pub schema: String,
    pub deployment_digest: Digest32,
    pub store_digest: Digest32,
    pub authority_identity: PublicKey,
    pub policy_count: u64,
    pub artifact_count: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectionKeyInput<'a> {
    domain: &'static str,
    evidence_id: &'a OpaqueReceiptRef,
    finding: &'a CorrelatedFindingReceiptBody,
    binding: &'a AttestedFindingBatchBinding,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactKeyInput<'a> {
    domain: &'static str,
    response_plan: &'a ResponsePlan,
    admission_artifact_ref: &'a AdmissionArtifactRef,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogicalStoreImage<'a> {
    schema: &'static str,
    authority_identity: &'a PublicKey,
    policies: &'a [LogicalRecord],
    artifacts: &'a [LogicalRecord],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogicalRecord {
    key: String,
    payload: serde_json::Value,
}

struct PreparedRecordSet {
    logical: Vec<LogicalRecord>,
    rows: Vec<(String, Vec<u8>)>,
}

struct ValidatedStoreContents {
    manifest: AuthorityStoreManifest,
    policies: BTreeMap<String, PreAdmittedPolicyRecord>,
    artifacts: BTreeMap<String, PreAdmittedArtifactRecord>,
}

pub fn selection_lookup_key(
    evidence_id: &OpaqueReceiptRef,
    finding: &CorrelatedFindingReceiptBody,
    binding: &AttestedFindingBatchBinding,
) -> Result<Digest32> {
    canonical_digest(&SelectionKeyInput {
        domain: AUTHORITY_SELECTION_KEY_DOMAIN,
        evidence_id,
        finding,
        binding,
    })
}

pub fn artifact_lookup_key(
    response_plan: &ResponsePlan,
    admission_artifact_ref: &AdmissionArtifactRef,
) -> Result<Digest32> {
    canonical_digest(&ArtifactKeyInput {
        domain: AUTHORITY_ARTIFACT_KEY_DOMAIN,
        response_plan,
        admission_artifact_ref,
    })
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<Digest32> {
    let bytes = canonical_json_bytes(value).map_err(|error| {
        AuthorityError::Invariant(format!("canonical digest encoding failed: {error}"))
    })?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Ok(Digest32::new(digest))
}

pub fn build_authority_store(
    bundle: &AuthorityStoreBundle,
    database_path: &Path,
    manifest_path: &Path,
) -> Result<AuthorityStoreManifest> {
    validate_bundle_header(bundle, database_path, manifest_path)?;
    let policies = prepare_policy_records(bundle)?;
    let artifacts = prepare_artifact_records(bundle)?;
    let store_digest = logical_store_digest(
        &bundle.authority_identity,
        &policies.logical,
        &artifacts.logical,
    )?;
    let manifest = AuthorityStoreManifest {
        schema: AUTHORITY_STORE_MANIFEST_SCHEMA.to_string(),
        deployment_digest: bundle.deployment_digest,
        store_digest,
        authority_identity: bundle.authority_identity.clone(),
        policy_count: u64::try_from(policies.rows.len())
            .map_err(|_| AuthorityError::Invariant("policy count overflow".to_string()))?,
        artifact_count: u64::try_from(artifacts.rows.len())
            .map_err(|_| AuthorityError::Invariant("artifact count overflow".to_string()))?,
    };

    let expected_uid = rustix::process::geteuid().as_raw();
    validate_private_parent(database_path, expected_uid)?;
    validate_private_parent(manifest_path, expected_uid)?;
    if database_path.exists() || manifest_path.exists() {
        return Err(AuthorityError::Custody(
            "authority store outputs already exist".to_string(),
        ));
    }

    let database_file = create_private_new_file(database_path)?;
    let mut database_guard = CreatedFileGuard::new(database_path, &database_file)?;
    drop(database_file);
    let mut connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| AuthorityError::Store(format!("database open failed: {error}")))?;
    validate_sqlite_identity(&connection, database_guard.identity)?;
    initialize_database(&mut connection, &manifest, &policies.rows, &artifacts.rows)?;
    connection
        .close()
        .map_err(|(_, error)| AuthorityError::Store(format!("database close failed: {error}")))?;
    database_guard.validate_exact()?;
    let _database_identity = validate_private_file(database_path, expected_uid)?;
    sync_private_file(database_path)?;

    let manifest_bytes = canonical_json_bytes(&manifest)
        .map_err(|error| AuthorityError::Invariant(format!("manifest encoding failed: {error}")))?;
    let mut manifest_file = create_private_new_file(manifest_path)?;
    let mut manifest_guard = CreatedFileGuard::new(manifest_path, &manifest_file)?;
    manifest_file
        .write_all(&manifest_bytes)
        .and_then(|()| manifest_file.sync_all())
        .map_err(|error| AuthorityError::Store(format!("manifest write failed: {error}")))?;
    manifest_file
        .seek(SeekFrom::Start(0))
        .map_err(|error| AuthorityError::Store(format!("manifest rewind failed: {error}")))?;
    let mut verified_manifest_bytes = Vec::with_capacity(manifest_bytes.len());
    Read::by_ref(&mut manifest_file)
        .take(
            u64::try_from(manifest_bytes.len())
                .map_err(|_| AuthorityError::Invariant("manifest size overflow".to_string()))?
                .saturating_add(1),
        )
        .read_to_end(&mut verified_manifest_bytes)
        .map_err(|error| AuthorityError::Store(format!("manifest reread failed: {error}")))?;
    if verified_manifest_bytes != manifest_bytes {
        return Err(AuthorityError::Custody(
            "manifest content changed during creation".to_string(),
        ));
    }
    drop(manifest_file);
    manifest_guard.validate_exact()?;
    let _manifest_identity = validate_private_file(manifest_path, expected_uid)?;

    let reopened = AuthorityStore::open(
        database_path,
        expected_uid,
        manifest.deployment_digest,
        manifest.store_digest,
        &manifest.authority_identity,
    )?;
    reopened.health()?;
    sync_output_parent(database_path)?;
    if database_path.parent() != manifest_path.parent() {
        sync_output_parent(manifest_path)?;
    }
    database_guard.disarm();
    manifest_guard.disarm();
    Ok(manifest)
}

fn validate_bundle_header(
    bundle: &AuthorityStoreBundle,
    database_path: &Path,
    manifest_path: &Path,
) -> Result<()> {
    validate_bundle_content(bundle)?;
    if bundle.deployment_digest.is_zero()
        || !valid_output_path(database_path)
        || !valid_output_path(manifest_path)
        || database_path == manifest_path
    {
        return Err(AuthorityError::InvalidConfig(
            "store bundle schema, digest, record bounds, or output paths are invalid".to_string(),
        ));
    }
    Ok(())
}

fn valid_output_path(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && !path.as_os_str().as_encoded_bytes().contains(&0)
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn validate_bundle_content(bundle: &AuthorityStoreBundle) -> Result<()> {
    if bundle.schema != AUTHORITY_STORE_BUNDLE_SCHEMA
        || bundle.policies.is_empty()
        || bundle.artifacts.is_empty()
        || bundle.policies.len() > MAX_STORE_RECORDS
        || bundle.artifacts.len() > MAX_STORE_RECORDS
    {
        return Err(AuthorityError::InvalidConfig(
            "store bundle schema or record bounds are invalid".to_string(),
        ));
    }
    Ok(())
}

/// Compute the immutable content digest before the deployment digest exists.
///
/// The bundle's deployment digest is intentionally excluded. This supports a
/// two-phase workflow: digest reviewed records, bind that digest into the
/// deployment, then build the final store with the resulting deployment digest.
pub fn compute_authority_store_digest(bundle: &AuthorityStoreBundle) -> Result<Digest32> {
    validate_bundle_content(bundle)?;
    let policies = prepare_policy_records(bundle)?;
    let artifacts = prepare_artifact_records(bundle)?;
    logical_store_digest(
        &bundle.authority_identity,
        &policies.logical,
        &artifacts.logical,
    )
}

fn prepare_policy_records(bundle: &AuthorityStoreBundle) -> Result<PreparedRecordSet> {
    let mut records = BTreeMap::new();
    for record in &bundle.policies {
        validate_active_response_policy_selection(
            &record.evidence_id,
            &record.binding,
            &record.selection,
        )
        .map_err(|_| AuthorityError::InvalidConfig("policy record is inconsistent".to_string()))?;
        let key = digest_hex(selection_lookup_key(
            &record.evidence_id,
            &record.finding,
            &record.binding,
        )?);
        let payload = canonical_json_bytes(record).map_err(|error| {
            AuthorityError::InvalidConfig(format!("policy record encoding failed: {error}"))
        })?;
        validate_payload_size(&payload)?;
        if records.insert(key, payload).is_some() {
            return Err(AuthorityError::InvalidConfig(
                "duplicate policy lookup key".to_string(),
            ));
        }
    }
    prepare_logical_records(records)
}

fn prepare_artifact_records(bundle: &AuthorityStoreBundle) -> Result<PreparedRecordSet> {
    let mut records = BTreeMap::new();
    for record in &bundle.artifacts {
        validate_active_response_artifacts_draft(
            &record.response_plan,
            &record.admission_artifact_ref,
            &bundle.authority_identity,
            &record.draft,
        )
        .map_err(|_| {
            AuthorityError::InvalidConfig("admission artifact record is inconsistent".to_string())
        })?;
        let key = digest_hex(artifact_lookup_key(
            &record.response_plan,
            &record.admission_artifact_ref,
        )?);
        let payload = canonical_json_bytes(record).map_err(|error| {
            AuthorityError::InvalidConfig(format!("artifact record encoding failed: {error}"))
        })?;
        validate_payload_size(&payload)?;
        if records.insert(key, payload).is_some() {
            return Err(AuthorityError::InvalidConfig(
                "duplicate artifact lookup key".to_string(),
            ));
        }
    }
    prepare_logical_records(records)
}

fn prepare_logical_records(records: BTreeMap<String, Vec<u8>>) -> Result<PreparedRecordSet> {
    let mut logical = Vec::with_capacity(records.len());
    let mut rows = Vec::with_capacity(records.len());
    for (key, payload) in records {
        let value = serde_json::from_slice(&payload).map_err(|error| {
            AuthorityError::Invariant(format!("prepared record decode failed: {error}"))
        })?;
        logical.push(LogicalRecord {
            key: key.clone(),
            payload: value,
        });
        rows.push((key, payload));
    }
    Ok(PreparedRecordSet { logical, rows })
}

fn logical_store_digest(
    authority_identity: &PublicKey,
    policies: &[LogicalRecord],
    artifacts: &[LogicalRecord],
) -> Result<Digest32> {
    let image = LogicalStoreImage {
        schema: AUTHORITY_STORE_MANIFEST_SCHEMA,
        authority_identity,
        policies,
        artifacts,
    };
    let canonical = canonical_json_bytes(&image).map_err(|error| {
        AuthorityError::Invariant(format!("logical store encoding failed: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_STORE_LOGICAL_DOMAIN);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}

fn initialize_database(
    connection: &mut Connection,
    manifest: &AuthorityStoreManifest,
    policies: &[(String, Vec<u8>)],
    artifacts: &[(String, Vec<u8>)],
) -> Result<()> {
    connection
        .execute_batch(
            "PRAGMA trusted_schema=OFF;
             PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             PRAGMA secure_delete=ON;
             PRAGMA application_id=1128810831;
             PRAGMA user_version=1;",
        )
        .map_err(|error| AuthorityError::Store(format!("database schema failed: {error}")))?;
    connection
        .execute_batch(AUTHORITY_STORE_SCHEMA_SQL)
        .map_err(|error| AuthorityError::Store(format!("database schema failed: {error}")))?;
    let transaction = connection
        .transaction()
        .map_err(|error| AuthorityError::Store(format!("database transaction failed: {error}")))?;
    let metadata = [
        ("schema", canonical_json_bytes(&manifest.schema)),
        (
            "deployment_digest",
            canonical_json_bytes(&manifest.deployment_digest),
        ),
        ("store_digest", canonical_json_bytes(&manifest.store_digest)),
        (
            "authority_identity",
            canonical_json_bytes(&manifest.authority_identity),
        ),
        ("policy_count", canonical_json_bytes(&manifest.policy_count)),
        (
            "artifact_count",
            canonical_json_bytes(&manifest.artifact_count),
        ),
    ];
    for (key, value) in metadata {
        let value = value.map_err(|error| {
            AuthorityError::Invariant(format!("metadata encoding failed: {error}"))
        })?;
        transaction
            .execute(
                "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|error| AuthorityError::Store(format!("metadata insert failed: {error}")))?;
    }
    insert_rows(&transaction, "policies", policies)?;
    insert_rows(&transaction, "artifacts", artifacts)?;
    transaction
        .commit()
        .map_err(|error| AuthorityError::Store(format!("database commit failed: {error}")))?;
    connection
        .execute_batch("VACUUM;")
        .map_err(|error| AuthorityError::Store(format!("database finalization failed: {error}")))?;
    Ok(())
}

fn insert_rows(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    rows: &[(String, Vec<u8>)],
) -> Result<()> {
    let sql = match table {
        "policies" => "INSERT INTO policies (lookup_key, payload) VALUES (?1, ?2)",
        "artifacts" => "INSERT INTO artifacts (lookup_key, payload) VALUES (?1, ?2)",
        _ => {
            return Err(AuthorityError::Invariant(
                "unknown authority store table".to_string(),
            ))
        }
    };
    for (key, payload) in rows {
        transaction
            .execute(sql, params![key, payload])
            .map_err(|error| AuthorityError::Store(format!("record insert failed: {error}")))?;
    }
    Ok(())
}

pub struct AuthorityStore {
    connection: Mutex<Connection>,
    manifest: AuthorityStoreManifest,
    policies: BTreeMap<String, PreAdmittedPolicyRecord>,
    artifacts: BTreeMap<String, PreAdmittedArtifactRecord>,
    path: PathBuf,
    trusted_service_uid: u32,
    file_identity: FileIdentity,
}

impl AuthorityStore {
    pub fn open(
        path: &Path,
        trusted_service_uid: u32,
        expected_deployment_digest: Digest32,
        expected_store_digest: Digest32,
        expected_authority_identity: &PublicKey,
    ) -> Result<Self> {
        if expected_deployment_digest.is_zero() || expected_store_digest.is_zero() {
            return Err(AuthorityError::InvalidConfig(
                "expected deployment and store digests must be nonzero".to_string(),
            ));
        }
        let expected_identity = validate_private_file(path, trusted_service_uid)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| {
            AuthorityError::Store(format!("read-only database open failed: {error}"))
        })?;
        validate_sqlite_identity(&connection, expected_identity)?;
        if validate_private_file(path, trusted_service_uid)? != expected_identity {
            return Err(AuthorityError::Custody(
                "store path identity changed while it was opened".to_string(),
            ));
        }
        connection
            .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|error| AuthorityError::Store(format!("read-only mode failed: {error}")))?;
        let validated = validate_store_contents(
            &connection,
            expected_deployment_digest,
            expected_store_digest,
            expected_authority_identity,
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            manifest: validated.manifest,
            policies: validated.policies,
            artifacts: validated.artifacts,
            path: path.to_path_buf(),
            trusted_service_uid,
            file_identity: expected_identity,
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &AuthorityStoreManifest {
        &self.manifest
    }

    pub fn health(&self) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| {
            AuthorityError::Invariant("authority store mutex was poisoned".to_string())
        })?;
        validate_sqlite_identity(&connection, self.file_identity)?;
        if validate_private_file(&self.path, self.trusted_service_uid)? != self.file_identity {
            return Err(AuthorityError::Custody(
                "authority store path identity changed after open".to_string(),
            ));
        }
        let observed = validate_store_contents(
            &connection,
            self.manifest.deployment_digest,
            self.manifest.store_digest,
            &self.manifest.authority_identity,
        )?;
        if observed.manifest != self.manifest {
            return Err(AuthorityError::Custody(
                "authority store manifest changed after open".to_string(),
            ));
        }
        Ok(())
    }

    pub fn select_policy(
        &self,
        evidence_id: &OpaqueReceiptRef,
        finding: &CorrelatedFindingReceiptBody,
        binding: &AttestedFindingBatchBinding,
    ) -> Result<ActiveResponsePolicySelectionWire> {
        let key = digest_hex(selection_lookup_key(evidence_id, finding, binding)?);
        let record = self.policy_record(&key)?;
        if record.evidence_id != *evidence_id
            || record.finding != *finding
            || record.binding != *binding
        {
            return Err(AuthorityError::Custody(
                "policy lookup returned a mismatched record".to_string(),
            ));
        }
        validate_active_response_policy_selection(evidence_id, binding, &record.selection)
            .map_err(|_| AuthorityError::Custody("stored policy is inconsistent".to_string()))?;
        Ok(record.selection.clone())
    }

    pub fn load_artifacts(
        &self,
        response_plan: &ResponsePlan,
        admission_artifact_ref: &AdmissionArtifactRef,
    ) -> Result<ActiveResponseAdmissionArtifactsDraftWire> {
        let key = digest_hex(artifact_lookup_key(response_plan, admission_artifact_ref)?);
        let record = self.artifact_record(&key)?;
        if record.response_plan != *response_plan
            || record.admission_artifact_ref != *admission_artifact_ref
        {
            return Err(AuthorityError::Custody(
                "artifact lookup returned a mismatched record".to_string(),
            ));
        }
        validate_active_response_artifacts_draft(
            response_plan,
            admission_artifact_ref,
            &self.manifest.authority_identity,
            &record.draft,
        )
        .map_err(|_| AuthorityError::Custody("stored artifact is inconsistent".to_string()))?;
        Ok(record.draft.clone())
    }

    fn policy_record(&self, key: &str) -> Result<&PreAdmittedPolicyRecord> {
        self.policies.get(key).ok_or(AuthorityError::NotPreAdmitted)
    }

    fn artifact_record(&self, key: &str) -> Result<&PreAdmittedArtifactRecord> {
        self.artifacts
            .get(key)
            .ok_or(AuthorityError::NotPreAdmitted)
    }
}

fn validate_store_contents(
    connection: &Connection,
    expected_deployment_digest: Digest32,
    expected_store_digest: Digest32,
    expected_authority_identity: &PublicKey,
) -> Result<ValidatedStoreContents> {
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|error| AuthorityError::Store(format!("integrity check failed: {error}")))?;
    if quick_check != "ok" {
        return Err(AuthorityError::Store(
            "SQLite integrity check did not pass".to_string(),
        ));
    }
    validate_database_schema(connection)?;
    let manifest = load_manifest(connection)?;
    if manifest.schema != AUTHORITY_STORE_MANIFEST_SCHEMA
        || manifest.deployment_digest != expected_deployment_digest
        || manifest.store_digest != expected_store_digest
        || &manifest.authority_identity != expected_authority_identity
    {
        return Err(AuthorityError::Custody(
            "store manifest does not match the pinned deployment".to_string(),
        ));
    }
    let policies = load_logical_records(connection, "policies")?;
    let artifacts = load_logical_records(connection, "artifacts")?;
    if usize::try_from(manifest.policy_count).ok() != Some(policies.len())
        || usize::try_from(manifest.artifact_count).ok() != Some(artifacts.len())
        || logical_store_digest(&manifest.authority_identity, &policies, &artifacts)?
            != manifest.store_digest
    {
        return Err(AuthorityError::Custody(
            "store logical digest or record counts do not match".to_string(),
        ));
    }
    let policies = validate_policy_records(policies)?;
    let artifacts = validate_artifact_records(artifacts, &manifest.authority_identity)?;
    Ok(ValidatedStoreContents {
        manifest,
        policies,
        artifacts,
    })
}

fn validate_database_schema(connection: &Connection) -> Result<()> {
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|error| AuthorityError::Store(format!("application ID failed: {error}")))?;
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| AuthorityError::Store(format!("schema version failed: {error}")))?;
    if application_id != AUTHORITY_STORE_APPLICATION_ID
        || user_version != AUTHORITY_STORE_USER_VERSION
    {
        return Err(AuthorityError::Custody(
            "authority store application or schema version is invalid".to_string(),
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '')
             FROM sqlite_schema
             ORDER BY type, name",
        )
        .map_err(|error| AuthorityError::Store(format!("schema inventory failed: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| AuthorityError::Store(format!("schema inventory failed: {error}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| AuthorityError::Store(format!("schema inventory failed: {error}")))?;
    let expected = vec![
        (
            "index".to_string(),
            "sqlite_autoindex_artifacts_1".to_string(),
            "artifacts".to_string(),
            String::new(),
        ),
        (
            "index".to_string(),
            "sqlite_autoindex_metadata_1".to_string(),
            "metadata".to_string(),
            String::new(),
        ),
        (
            "index".to_string(),
            "sqlite_autoindex_policies_1".to_string(),
            "policies".to_string(),
            String::new(),
        ),
        (
            "table".to_string(),
            "artifacts".to_string(),
            "artifacts".to_string(),
            "CREATE TABLE artifacts (lookup_key TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL) STRICT"
                .to_string(),
        ),
        (
            "table".to_string(),
            "metadata".to_string(),
            "metadata".to_string(),
            "CREATE TABLE metadata (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL) STRICT"
                .to_string(),
        ),
        (
            "table".to_string(),
            "policies".to_string(),
            "policies".to_string(),
            "CREATE TABLE policies (lookup_key TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL) STRICT"
                .to_string(),
        ),
    ];
    if rows != expected {
        return Err(AuthorityError::Custody(
            "authority store schema inventory is not exact".to_string(),
        ));
    }
    Ok(())
}

pub struct PreAdmittedAuthorityHandler {
    store: Arc<AuthorityStore>,
}

impl PreAdmittedAuthorityHandler {
    #[must_use]
    pub const fn new(store: Arc<AuthorityStore>) -> Self {
        Self { store }
    }

    fn map_lookup<T>(result: Result<T>) -> ActiveResponseAuthorityHandlerResult<T> {
        match result {
            Ok(value) => Ok(value),
            Err(AuthorityError::NotPreAdmitted) => {
                let code = ErrorCode::new("active_response.not_pre_admitted").map_err(|_| {
                    ActiveResponseAuthorityHandlerError::Fatal(PortError::integrity_failure())
                })?;
                Err(ActiveResponseAuthorityRejection::permanent(code).into())
            }
            Err(_) => Err(ActiveResponseAuthorityHandlerError::Fatal(
                PortError::integrity_failure(),
            )),
        }
    }
}

impl ActiveResponseAuthorityHandler for PreAdmittedAuthorityHandler {
    fn health(&self) -> ActiveResponseAuthorityHandlerResult<()> {
        self.store
            .health()
            .map_err(|_| ActiveResponseAuthorityHandlerError::Fatal(PortError::integrity_failure()))
    }

    fn select_policy(
        &self,
        evidence_id: &OpaqueReceiptRef,
        finding: &CorrelatedFindingReceiptBody,
        binding: &AttestedFindingBatchBinding,
    ) -> ActiveResponseAuthorityHandlerResult<ActiveResponsePolicySelectionWire> {
        Self::map_lookup(self.store.select_policy(evidence_id, finding, binding))
    }

    fn load_artifacts(
        &self,
        response_plan: &ResponsePlan,
        admission_artifact_ref: &AdmissionArtifactRef,
    ) -> ActiveResponseAuthorityHandlerResult<ActiveResponseAdmissionArtifactsDraftWire> {
        Self::map_lookup(
            self.store
                .load_artifacts(response_plan, admission_artifact_ref),
        )
    }
}

fn load_manifest(connection: &Connection) -> Result<AuthorityStoreManifest> {
    let mut statement = connection
        .prepare("SELECT key FROM metadata ORDER BY key")
        .map_err(|error| AuthorityError::Store(format!("metadata inventory failed: {error}")))?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| AuthorityError::Store(format!("metadata inventory failed: {error}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| AuthorityError::Store(format!("metadata inventory failed: {error}")))?;
    let expected_keys = [
        "artifact_count",
        "authority_identity",
        "deployment_digest",
        "policy_count",
        "schema",
        "store_digest",
    ];
    if keys
        .iter()
        .map(String::as_str)
        .ne(expected_keys.iter().copied())
    {
        return Err(AuthorityError::Custody(
            "authority store metadata inventory is not exact".to_string(),
        ));
    }
    Ok(AuthorityStoreManifest {
        schema: load_metadata(connection, "schema")?,
        deployment_digest: load_metadata(connection, "deployment_digest")?,
        store_digest: load_metadata(connection, "store_digest")?,
        authority_identity: load_metadata(connection, "authority_identity")?,
        policy_count: load_metadata(connection, "policy_count")?,
        artifact_count: load_metadata(connection, "artifact_count")?,
    })
}

fn load_metadata<T: DeserializeOwned + Serialize>(connection: &Connection, key: &str) -> Result<T> {
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .map_err(|error| AuthorityError::Store(format!("metadata lookup failed: {error}")))?;
    decode_canonical(&bytes, "store metadata")
}

fn load_logical_records(connection: &Connection, table: &str) -> Result<Vec<LogicalRecord>> {
    let sql = match table {
        "policies" => "SELECT lookup_key, payload FROM policies ORDER BY lookup_key",
        "artifacts" => "SELECT lookup_key, payload FROM artifacts ORDER BY lookup_key",
        _ => {
            return Err(AuthorityError::Invariant(
                "unknown authority store table".to_string(),
            ))
        }
    };
    let mut statement = connection
        .prepare(sql)
        .map_err(|error| AuthorityError::Store(format!("record scan failed: {error}")))?;
    let mut rows = statement
        .query([])
        .map_err(|error| AuthorityError::Store(format!("record query failed: {error}")))?;
    let mut records = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| AuthorityError::Store(format!("record read failed: {error}")))?
    {
        if records.len() >= MAX_STORE_RECORDS {
            return Err(AuthorityError::Custody(
                "authority store record count exceeds the limit".to_string(),
            ));
        }
        let key: String = row
            .get(0)
            .map_err(|error| AuthorityError::Store(format!("record key failed: {error}")))?;
        let payload: Vec<u8> = row
            .get(1)
            .map_err(|error| AuthorityError::Store(format!("record payload failed: {error}")))?;
        validate_payload_size(&payload)?;
        validate_lookup_key(&key)?;
        let value: serde_json::Value = decode_canonical(&payload, "stored record")?;
        records.push(LogicalRecord {
            key,
            payload: value,
        });
    }
    Ok(records)
}

fn validate_policy_records(
    records: Vec<LogicalRecord>,
) -> Result<BTreeMap<String, PreAdmittedPolicyRecord>> {
    let mut validated = BTreeMap::new();
    for logical in records {
        let record: PreAdmittedPolicyRecord = serde_json::from_value(logical.payload)
            .map_err(|error| AuthorityError::Custody(format!("policy decode failed: {error}")))?;
        validate_active_response_policy_selection(
            &record.evidence_id,
            &record.binding,
            &record.selection,
        )
        .map_err(|_| AuthorityError::Custody("stored policy is inconsistent".to_string()))?;
        if logical.key
            != digest_hex(selection_lookup_key(
                &record.evidence_id,
                &record.finding,
                &record.binding,
            )?)
        {
            return Err(AuthorityError::Custody(
                "stored policy lookup key is inconsistent".to_string(),
            ));
        }
        if validated.insert(logical.key, record).is_some() {
            return Err(AuthorityError::Custody(
                "stored policy lookup keys are not unique".to_string(),
            ));
        }
    }
    Ok(validated)
}

fn validate_artifact_records(
    records: Vec<LogicalRecord>,
    authority: &PublicKey,
) -> Result<BTreeMap<String, PreAdmittedArtifactRecord>> {
    let mut validated = BTreeMap::new();
    for logical in records {
        let record: PreAdmittedArtifactRecord = serde_json::from_value(logical.payload)
            .map_err(|error| AuthorityError::Custody(format!("artifact decode failed: {error}")))?;
        validate_active_response_artifacts_draft(
            &record.response_plan,
            &record.admission_artifact_ref,
            authority,
            &record.draft,
        )
        .map_err(|_| AuthorityError::Custody("stored artifact is inconsistent".to_string()))?;
        if logical.key
            != digest_hex(artifact_lookup_key(
                &record.response_plan,
                &record.admission_artifact_ref,
            )?)
        {
            return Err(AuthorityError::Custody(
                "stored artifact lookup key is inconsistent".to_string(),
            ));
        }
        if validated.insert(logical.key, record).is_some() {
            return Err(AuthorityError::Custody(
                "stored artifact lookup keys are not unique".to_string(),
            ));
        }
    }
    Ok(validated)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8], label: &str) -> Result<T> {
    validate_payload_size(bytes)?;
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| AuthorityError::Custody(format!("{label} decode failed: {error}")))?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| AuthorityError::Custody(format!("{label} encoding failed: {error}")))?;
    if canonical != bytes {
        return Err(AuthorityError::Custody(format!(
            "{label} is not canonical JSON"
        )));
    }
    Ok(value)
}

fn validate_payload_size(payload: &[u8]) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_STORE_PAYLOAD_BYTES {
        return Err(AuthorityError::Custody(
            "authority store payload is empty or oversized".to_string(),
        ));
    }
    Ok(())
}

fn validate_lookup_key(key: &str) -> Result<()> {
    if key.len() != 64
        || !key
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(AuthorityError::Custody(
            "authority store lookup key is not canonical lowercase hex".to_string(),
        ));
    }
    Ok(())
}

fn digest_hex(digest: Digest32) -> String {
    hex::encode(digest.as_bytes())
}

fn create_private_new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|error| AuthorityError::Custody(format!("output create failed: {error}")))
}

#[cfg(unix)]
fn sync_private_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| AuthorityError::Store(format!("output sync failed: {error}")))
}

#[cfg(not(unix))]
fn sync_private_file(_path: &Path) -> Result<()> {
    Err(AuthorityError::Custody(
        "authority stores require Unix file custody".to_string(),
    ))
}

#[cfg(unix)]
fn sync_output_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        AuthorityError::InvalidConfig("output path has no parent directory".to_string())
    })?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    options
        .open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| AuthorityError::Store(format!("output directory sync failed: {error}")))
}

#[cfg(not(unix))]
fn sync_output_parent(_path: &Path) -> Result<()> {
    Err(AuthorityError::Custody(
        "authority stores require Unix file custody".to_string(),
    ))
}

#[cfg(unix)]
fn validate_private_parent(path: &Path, expected_uid: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        AuthorityError::InvalidConfig("output path has no parent directory".to_string())
    })?;
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| AuthorityError::Custody(format!("output parent failed: {error}")))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AuthorityError::Custody(
            "output parent must be a private directory owned by the builder".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_parent(_path: &Path, _expected_uid: u32) -> Result<()> {
    Err(AuthorityError::Custody(
        "authority stores require Unix file custody".to_string(),
    ))
}

#[cfg(unix)]
fn validate_private_file(path: &Path, expected_uid: u32) -> Result<FileIdentity> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| AuthorityError::Custody(format!("store metadata failed: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_STORE_FILE_BYTES
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AuthorityError::Custody(
            "store ownership, link count, or permissions are invalid".to_string(),
        ));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn validate_private_file(_path: &Path, _expected_uid: u32) -> Result<FileIdentity> {
    Err(AuthorityError::Custody(
        "authority stores require Unix file custody".to_string(),
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn validate_sqlite_identity(connection: &Connection, expected: FileIdentity) -> Result<()> {
    let actual = main_database_file_identity(connection).map_err(AuthorityError::Custody)?;
    if actual.device != expected.device || actual.inode != expected.inode || actual.link_count != 1
    {
        return Err(AuthorityError::Custody(
            "SQLite opened a database outside the retained file identity".to_string(),
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
pub(crate) fn build_empty_store_for_process_test(
    path: &Path,
    deployment_digest: Digest32,
    authority_identity: &PublicKey,
) -> Result<Digest32> {
    let store_digest = logical_store_digest(authority_identity, &[], &[])?;
    let manifest = AuthorityStoreManifest {
        schema: AUTHORITY_STORE_MANIFEST_SCHEMA.to_string(),
        deployment_digest,
        store_digest,
        authority_identity: authority_identity.clone(),
        policy_count: 0,
        artifact_count: 0,
    };
    let expected_uid = rustix::process::geteuid().as_raw();
    validate_private_parent(path, expected_uid)?;
    let file = create_private_new_file(path)?;
    let mut guard = CreatedFileGuard::new(path, &file)?;
    drop(file);
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| AuthorityError::Store(format!("test database open failed: {error}")))?;
    validate_sqlite_identity(&connection, guard.identity)?;
    initialize_database(&mut connection, &manifest, &[], &[])?;
    connection.close().map_err(|(_, error)| {
        AuthorityError::Store(format!("test database close failed: {error}"))
    })?;
    guard.validate_exact()?;
    let _identity = validate_private_file(path, expected_uid)?;
    sync_private_file(path)?;
    sync_output_parent(path)?;
    guard.disarm();
    Ok(store_digest)
}

struct CreatedFileGuard {
    path: PathBuf,
    #[cfg(unix)]
    identity: FileIdentity,
    armed: bool,
}

impl CreatedFileGuard {
    fn new(path: &Path, file: &File) -> Result<Self> {
        #[cfg(unix)]
        {
            let metadata = file.metadata().map_err(|error| {
                AuthorityError::Custody(format!("created file metadata failed: {error}"))
            })?;
            Ok(Self {
                path: path.to_path_buf(),
                identity: FileIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
                armed: true,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Ok(Self {
                path: path.to_path_buf(),
                armed: true,
            })
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn validate_exact(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let metadata = std::fs::symlink_metadata(&self.path).map_err(|error| {
                AuthorityError::Custody(format!("created file path failed: {error}"))
            })?;
            if !metadata.file_type().is_file()
                || metadata.dev() != self.identity.device
                || metadata.ino() != self.identity.inode
            {
                return Err(AuthorityError::Custody(
                    "created output identity changed".to_string(),
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(AuthorityError::Custody(
                "authority stores require Unix file custody".to_string(),
            ))
        }
    }
}

impl Drop for CreatedFileGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(unix)]
        let exact = std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_file()
                && metadata.dev() == self.identity.device
                && metadata.ino() == self.identity.inode
        });
        #[cfg(not(unix))]
        let exact = false;
        if exact {
            let _remove_result = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests;
