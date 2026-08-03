use chio_core::capability::aggregate_budget::{
    verify_direct_aggregate_root_record, AggregateFamilyRootResolution,
    AggregateFamilyRootResolutionError, AggregateFamilyRootResolver,
};
use chio_core::capability::attenuation::scope_hash;
use chio_core::capability::token::CapabilityToken;
use chio_core::{
    canonical_json_bytes, canonical_json_bytes_from_str, sha256_hex, Error as CoreError, PublicKey,
};
use chio_kernel::ReceiptStoreError;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;
use std::time::Duration;

use crate::SqliteReceiptStore;

const AGGREGATE_FAMILY_ROOT_TOKEN_DIGEST_DOMAIN: &str = "chio.aggregate-family-root-record.v1\0";
/// Maximum canonical bytes accepted for one durable aggregate-root token.
pub const MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES: usize = 512 * 1024;
const AGGREGATE_FAMILY_ROOT_SCHEMA_VERSION: i64 = 1;
const AGGREGATE_FAMILY_ROOT_SCHEMA_FINGERPRINT: &str =
    "chio.aggregate-family-root-authority.sqlite.v1";
const AGGREGATE_FAMILY_ROOT_MODULE_NAME: &str = "aggregate_family_root_authority";

const MODULE_SCHEMA_VERSION_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS chio_module_schema_version (
    module TEXT PRIMARY KEY,
    version INTEGER NOT NULL
);
"#;

const AGGREGATE_FAMILY_ROOT_SENTINEL_TABLE_SQL: &str = r#"
CREATE TABLE chio_aggregate_family_root_schema (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    schema_fingerprint TEXT NOT NULL
);
"#;

const AGGREGATE_FAMILY_ROOT_TABLE_SQL: &str = r#"
CREATE TABLE chio_aggregate_family_roots (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    root_capability_id TEXT NOT NULL COLLATE BINARY UNIQUE,
    root_kind TEXT NOT NULL CHECK (root_kind IN ('legacy_unbound', 'family_bound')),
    canonical_token_json TEXT NOT NULL,
    token_digest TEXT NOT NULL CHECK (length(token_digest) = 64),
    issuer_key TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    root_scope_hash TEXT NOT NULL CHECK (length(root_scope_hash) = 64),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    family_binding_digest TEXT,
    family_owner TEXT,
    family_max_invocations INTEGER,
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
    CHECK (
        (root_kind = 'legacy_unbound'
            AND family_binding_digest IS NULL
            AND family_owner IS NULL
            AND family_max_invocations IS NULL)
        OR
        (root_kind = 'family_bound'
            AND family_binding_digest IS NOT NULL
            AND length(family_binding_digest) = 64
            AND family_owner IS NOT NULL
            AND length(family_owner) = 64
            AND family_max_invocations IS NOT NULL
            AND family_max_invocations BETWEEN 0 AND 4294967295)
    )
);
"#;

const AGGREGATE_FAMILY_ROOT_SENTINEL_INSERT_TRIGGER_SQL: &str = r#"
CREATE TRIGGER chio_aggregate_family_root_schema_immutable_insert
BEFORE INSERT ON chio_aggregate_family_root_schema
WHEN EXISTS (SELECT 1 FROM chio_aggregate_family_root_schema)
BEGIN
    SELECT RAISE(ABORT, 'aggregate family-root schema sentinel is immutable');
END;
"#;

const AGGREGATE_FAMILY_ROOT_SENTINEL_UPDATE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER chio_aggregate_family_root_schema_immutable_update
BEFORE UPDATE ON chio_aggregate_family_root_schema
BEGIN
    SELECT RAISE(ABORT, 'aggregate family-root schema sentinel is immutable');
END;
"#;

const AGGREGATE_FAMILY_ROOT_SENTINEL_DELETE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER chio_aggregate_family_root_schema_immutable_delete
BEFORE DELETE ON chio_aggregate_family_root_schema
BEGIN
    SELECT RAISE(ABORT, 'aggregate family-root schema sentinel is immutable');
END;
"#;

const AGGREGATE_FAMILY_ROOT_INSERT_TRIGGER_SQL: &str = r#"
CREATE TRIGGER chio_aggregate_family_roots_immutable_insert
BEFORE INSERT ON chio_aggregate_family_roots
WHEN EXISTS (
    SELECT 1
    FROM chio_aggregate_family_roots
    WHERE root_capability_id = NEW.root_capability_id
)
BEGIN
    SELECT RAISE(ABORT, 'aggregate family-root records are immutable');
END;
"#;

pub(crate) const AGGREGATE_FAMILY_ROOT_UPDATE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER chio_aggregate_family_roots_immutable_update
BEFORE UPDATE ON chio_aggregate_family_roots
BEGIN
    SELECT RAISE(ABORT, 'aggregate family-root records are immutable');
END;
"#;

const AGGREGATE_FAMILY_ROOT_DELETE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER chio_aggregate_family_roots_immutable_delete
BEFORE DELETE ON chio_aggregate_family_roots
BEGIN
    SELECT RAISE(ABORT, 'aggregate family-root records are immutable');
END;
"#;

const AGGREGATE_FAMILY_ROOT_SCHEMA_OBJECTS: &[(&str, &str, &str)] = &[
    (
        "table",
        "chio_aggregate_family_root_schema",
        AGGREGATE_FAMILY_ROOT_SENTINEL_TABLE_SQL,
    ),
    (
        "table",
        "chio_aggregate_family_roots",
        AGGREGATE_FAMILY_ROOT_TABLE_SQL,
    ),
    (
        "trigger",
        "chio_aggregate_family_root_schema_immutable_insert",
        AGGREGATE_FAMILY_ROOT_SENTINEL_INSERT_TRIGGER_SQL,
    ),
    (
        "trigger",
        "chio_aggregate_family_root_schema_immutable_update",
        AGGREGATE_FAMILY_ROOT_SENTINEL_UPDATE_TRIGGER_SQL,
    ),
    (
        "trigger",
        "chio_aggregate_family_root_schema_immutable_delete",
        AGGREGATE_FAMILY_ROOT_SENTINEL_DELETE_TRIGGER_SQL,
    ),
    (
        "trigger",
        "chio_aggregate_family_roots_immutable_insert",
        AGGREGATE_FAMILY_ROOT_INSERT_TRIGGER_SQL,
    ),
    (
        "trigger",
        "chio_aggregate_family_roots_immutable_update",
        AGGREGATE_FAMILY_ROOT_UPDATE_TRIGGER_SQL,
    ),
    (
        "trigger",
        "chio_aggregate_family_roots_immutable_delete",
        AGGREGATE_FAMILY_ROOT_DELETE_TRIGGER_SQL,
    ),
];

/// Outcome of an immutable aggregate family-root registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateFamilyRootRecordStatus {
    /// The authenticated root was durably inserted by this call.
    Inserted,
    /// The exact authenticated root was already durably present.
    AlreadyPresent,
}

/// Full authenticated root record carried by snapshot and delta replication.
#[derive(Clone, Debug)]
pub struct StoredAggregateFamilyRoot {
    pub seq: u64,
    pub canonical_token_json: String,
    pub token_digest: String,
}

/// Point lookup result and immutable stream head observed in one read snapshot.
#[derive(Clone, Debug)]
pub struct AggregateFamilyRootLookupSnapshot {
    pub high_watermark: u64,
    pub record: Option<StoredAggregateFamilyRoot>,
}

/// Typed failures from aggregate family-root registration.
#[derive(Debug, thiserror::Error)]
pub enum AggregateFamilyRootStoreError {
    /// The candidate root or its signing authority failed authentication.
    #[error("aggregate family-root authentication failed: {0}")]
    Authentication(String),
    /// The candidate is authenticated but is not a registrable direct root.
    #[error("invalid aggregate family-root record: {0}")]
    InvalidRecord(String),
    /// A different authenticated root already owns the immutable identifier.
    #[error("aggregate family-root identifier conflicts: {root_capability_id}")]
    Conflict { root_capability_id: String },
    /// Existing durable authority state is malformed or internally inconsistent.
    #[error("aggregate family-root store is corrupt: {0}")]
    Corrupt(String),
    /// The durable authority could not complete the operation.
    #[error("aggregate family-root store unavailable: {0}")]
    Unavailable(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredRootKind {
    LegacyUnbound,
    FamilyBound,
}

impl StoredRootKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::LegacyUnbound => "legacy_unbound",
            Self::FamilyBound => "family_bound",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RootRecord {
    root_capability_id: String,
    root_kind: StoredRootKind,
    canonical_token_json: String,
    token_digest: String,
    issuer_key: String,
    subject_key: String,
    root_scope_hash: String,
    issued_at: i64,
    expires_at: i64,
    family_binding_digest: Option<String>,
    family_owner: Option<String>,
    family_max_invocations: Option<i64>,
    recorded_at: i64,
}

#[derive(Clone, Debug)]
struct AuthenticatedRoot {
    record: RootRecord,
    resolution: AggregateFamilyRootResolution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IssuedRootLineage {
    capability_id: String,
    subject_key: String,
    issuer_key: String,
    issued_at: i64,
    expires_at: i64,
    grants_json: String,
    delegation_depth: i64,
    parent_capability_id: Option<String>,
}

#[derive(Debug)]
enum SchemaIntegrityError {
    Sqlite(rusqlite::Error),
    Corrupt(String),
}

impl From<rusqlite::Error> for SchemaIntegrityError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub(crate) fn ensure_aggregate_family_root_schema(
    connection: &mut Connection,
) -> Result<(), ReceiptStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let sentinel_present =
        sqlite_object_sql(&transaction, "table", "chio_aggregate_family_root_schema")?.is_some();
    let authority_present =
        sqlite_object_sql(&transaction, "table", "chio_aggregate_family_roots")?.is_some();
    transaction.execute_batch(MODULE_SCHEMA_VERSION_TABLE_SQL)?;
    let module_version = read_module_schema_version(&transaction)?;

    match (sentinel_present, authority_present, module_version) {
        (false, false, None | Some(0)) => {
            transaction.execute_batch(AGGREGATE_FAMILY_ROOT_SENTINEL_TABLE_SQL)?;
            transaction.execute_batch(AGGREGATE_FAMILY_ROOT_TABLE_SQL)?;
            transaction.execute(
                "INSERT INTO chio_aggregate_family_root_schema \
                 (singleton, schema_version, schema_fingerprint) VALUES (1, ?1, ?2)",
                params![
                    AGGREGATE_FAMILY_ROOT_SCHEMA_VERSION,
                    AGGREGATE_FAMILY_ROOT_SCHEMA_FINGERPRINT
                ],
            )?;
            transaction.execute_batch(AGGREGATE_FAMILY_ROOT_SENTINEL_INSERT_TRIGGER_SQL)?;
            transaction.execute_batch(AGGREGATE_FAMILY_ROOT_SENTINEL_UPDATE_TRIGGER_SQL)?;
            transaction.execute_batch(AGGREGATE_FAMILY_ROOT_SENTINEL_DELETE_TRIGGER_SQL)?;
            transaction.execute_batch(AGGREGATE_FAMILY_ROOT_INSERT_TRIGGER_SQL)?;
            transaction.execute_batch(AGGREGATE_FAMILY_ROOT_UPDATE_TRIGGER_SQL)?;
            transaction.execute_batch(AGGREGATE_FAMILY_ROOT_DELETE_TRIGGER_SQL)?;
            stamp_module_schema_version(&transaction)?;
        }
        (true, true, Some(AGGREGATE_FAMILY_ROOT_SCHEMA_VERSION)) => {}
        (true, true, None | Some(0)) => {
            validate_schema_integrity_without_module_version(&transaction)
                .map_err(schema_integrity_to_receipt_error)?;
            stamp_module_schema_version(&transaction)?;
        }
        _ => {
            return Err(ReceiptStoreError::Conflict(
                "aggregate family-root authority schema or durable version marker is incomplete"
                    .to_string(),
            ));
        }
    }

    validate_schema_integrity(&transaction).map_err(schema_integrity_to_receipt_error)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn validate_existing_aggregate_family_root_schema(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    validate_schema_integrity(connection).map_err(schema_integrity_to_receipt_error)
}

impl SqliteReceiptStore {
    /// Register one authenticated direct aggregate or explicit legacy root.
    pub fn record_aggregate_family_root(
        &self,
        token: &CapabilityToken,
        trusted_issuers: &[PublicKey],
        recorded_at: u64,
    ) -> Result<AggregateFamilyRootRecordStatus, AggregateFamilyRootStoreError> {
        let mut statuses = self.record_aggregate_family_roots(
            core::slice::from_ref(token),
            trusted_issuers,
            recorded_at,
        )?;
        statuses.pop().ok_or_else(|| {
            AggregateFamilyRootStoreError::Corrupt(
                "single-root registration returned no status".to_string(),
            )
        })
    }

    /// Atomically register a batch of authenticated direct roots.
    pub fn record_aggregate_family_roots(
        &self,
        tokens: &[CapabilityToken],
        trusted_issuers: &[PublicKey],
        recorded_at: u64,
    ) -> Result<Vec<AggregateFamilyRootRecordStatus>, AggregateFamilyRootStoreError> {
        let authenticated = tokens
            .iter()
            .map(|token| authenticate_root(token, trusted_issuers, recorded_at))
            .collect::<Result<Vec<_>, _>>()?;

        self.writer_handle()
            .run_write(move |connection| Ok(record_authenticated_roots(connection, &authenticated)))
            .map_err(receipt_store_unavailable)?
    }

    /// Atomically register an issued direct root and its lineage snapshot.
    pub fn record_issued_aggregate_family_root(
        &self,
        token: &CapabilityToken,
        trusted_issuers: &[PublicKey],
        recorded_at: u64,
    ) -> Result<AggregateFamilyRootRecordStatus, AggregateFamilyRootStoreError> {
        let authenticated = authenticate_root(token, trusted_issuers, recorded_at)?;
        let lineage = issued_root_lineage(token, &authenticated)?;

        self.writer_handle()
            .run_write(move |connection| {
                Ok(record_issued_root(connection, &authenticated, &lineage))
            })
            .map_err(receipt_store_unavailable)?
    }

    /// Load one exact root artifact and the local stream head atomically.
    pub fn lookup_aggregate_family_root(
        &self,
        root_capability_id: &str,
    ) -> Result<AggregateFamilyRootLookupSnapshot, AggregateFamilyRootStoreError> {
        let mut connection = self.connection().map_err(receipt_store_unavailable)?;
        lookup_aggregate_family_root_snapshot(&mut connection, root_capability_id)
    }

    /// Read one root from an existing authority without creating or repairing state.
    pub fn lookup_existing_aggregate_family_root(
        path: impl AsRef<Path>,
        root_capability_id: &str,
    ) -> Result<AggregateFamilyRootLookupSnapshot, AggregateFamilyRootStoreError> {
        let mut connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sqlite_to_store_error)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(sqlite_to_store_error)?;
        lookup_aggregate_family_root_snapshot(&mut connection, root_capability_id)
    }

    /// Highest local aggregate family-root sequence, or zero when empty.
    pub fn max_aggregate_family_root_seq(&self) -> Result<u64, AggregateFamilyRootStoreError> {
        let mut connection = self.connection().map_err(receipt_store_unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_to_store_error)?;
        validate_schema_integrity(&transaction).map_err(schema_integrity_to_store_error)?;
        let seq = transaction
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM chio_aggregate_family_roots",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_to_store_error)?;
        transaction.commit().map_err(sqlite_to_store_error)?;
        stored_sequence_u64(seq, "aggregate family-root head")
    }

    /// List authenticated full root tokens after a local sequence.
    pub fn list_aggregate_family_roots_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredAggregateFamilyRoot>, AggregateFamilyRootStoreError> {
        let limit = i64::try_from(limit).map_err(|_| {
            AggregateFamilyRootStoreError::InvalidRecord(
                "aggregate family-root list limit exceeds the SQLite INTEGER range".to_string(),
            )
        })?;
        let after_seq = i64::try_from(after_seq).map_err(|_| {
            AggregateFamilyRootStoreError::InvalidRecord(
                "aggregate family-root cursor exceeds the SQLite INTEGER range".to_string(),
            )
        })?;
        let mut connection = self.connection().map_err(receipt_store_unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_to_store_error)?;
        validate_schema_integrity(&transaction).map_err(schema_integrity_to_store_error)?;
        let mut statement = transaction
            .prepare(
                "SELECT seq, root_capability_id \
                 FROM chio_aggregate_family_roots \
                 WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2",
            )
            .map_err(sqlite_to_store_error)?;
        let indexed_roots = statement
            .query_map(params![after_seq, limit], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_to_store_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_to_store_error)?;
        drop(statement);

        let mut records = Vec::with_capacity(indexed_roots.len());
        for (seq, root_capability_id) in indexed_roots {
            let stored = load_root_record(&transaction, &root_capability_id)
                .map_err(sqlite_to_store_error)?
                .ok_or_else(|| {
                    AggregateFamilyRootStoreError::Corrupt(format!(
                        "aggregate family-root sequence {seq} has no record"
                    ))
                })?;
            let authenticated = validate_stored_root(stored)?;
            records.push(StoredAggregateFamilyRoot {
                seq: stored_sequence_u64(seq, "aggregate family-root sequence")?,
                canonical_token_json: authenticated.record.canonical_token_json,
                token_digest: authenticated.record.token_digest,
            });
        }
        transaction.commit().map_err(sqlite_to_store_error)?;
        Ok(records)
    }

    /// Reauthenticate and atomically import one ordered root page.
    pub fn import_aggregate_family_roots(
        &self,
        records: &[StoredAggregateFamilyRoot],
        trusted_issuers: &[PublicKey],
        recorded_at: u64,
    ) -> Result<Vec<AggregateFamilyRootRecordStatus>, AggregateFamilyRootStoreError> {
        let mut previous_seq = None;
        let authenticated = records
            .iter()
            .map(|record| {
                if record.seq == 0 || previous_seq.is_some_and(|previous| record.seq <= previous) {
                    return Err(AggregateFamilyRootStoreError::InvalidRecord(
                        "aggregate family-root replication sequence is not strictly increasing"
                            .to_string(),
                    ));
                }
                previous_seq = Some(record.seq);
                authenticate_replication_root(record, trusted_issuers, recorded_at)
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.writer_handle()
            .run_write(move |connection| Ok(record_authenticated_roots(connection, &authenticated)))
            .map_err(receipt_store_unavailable)?
    }
}

fn lookup_aggregate_family_root_snapshot(
    connection: &mut Connection,
    root_capability_id: &str,
) -> Result<AggregateFamilyRootLookupSnapshot, AggregateFamilyRootStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(sqlite_to_store_error)?;
    validate_schema_integrity(&transaction).map_err(schema_integrity_to_store_error)?;
    let high_watermark = transaction
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_aggregate_family_roots",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_to_store_error)?;
    let seq = transaction
        .query_row(
            "SELECT seq FROM chio_aggregate_family_roots WHERE root_capability_id = ?1",
            params![root_capability_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_to_store_error)?;
    let record = match seq {
        Some(seq) => {
            let stored = load_root_record(&transaction, root_capability_id)
                .map_err(sqlite_to_store_error)?
                .ok_or_else(|| {
                    AggregateFamilyRootStoreError::Corrupt(format!(
                        "aggregate family-root sequence {seq} has no record"
                    ))
                })?;
            let authenticated = validate_stored_root(stored)?;
            Some(StoredAggregateFamilyRoot {
                seq: stored_sequence_u64(seq, "aggregate family-root sequence")?,
                canonical_token_json: authenticated.record.canonical_token_json,
                token_digest: authenticated.record.token_digest,
            })
        }
        None => None,
    };
    transaction.commit().map_err(sqlite_to_store_error)?;
    Ok(AggregateFamilyRootLookupSnapshot {
        high_watermark: stored_sequence_u64(high_watermark, "aggregate family-root head")?,
        record,
    })
}

impl AggregateFamilyRootResolver for SqliteReceiptStore {
    fn resolve_aggregate_family_root(
        &self,
        root_capability_id: &str,
    ) -> Result<AggregateFamilyRootResolution, AggregateFamilyRootResolutionError> {
        let mut connection = self
            .connection()
            .map_err(|error| AggregateFamilyRootResolutionError::Unavailable(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_to_resolution_error)?;
        validate_schema_integrity(&transaction).map_err(schema_integrity_to_resolution_error)?;
        let row = load_root_record(&transaction, root_capability_id)
            .map_err(sqlite_to_resolution_error)?
            .ok_or(AggregateFamilyRootResolutionError::Missing)?;
        transaction.commit().map_err(sqlite_to_resolution_error)?;
        validate_stored_root(row)
            .map(|root| root.resolution)
            .map_err(store_to_resolution_error)
    }
}

fn authenticate_root(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    recorded_at: u64,
) -> Result<AuthenticatedRoot, AggregateFamilyRootStoreError> {
    let issued_at = sqlite_record_i64(token.issued_at, "issued_at")?;
    let expires_at = sqlite_record_i64(token.expires_at, "expires_at")?;
    let recorded_at = sqlite_record_i64(recorded_at, "recorded_at")?;
    let resolution = verify_direct_aggregate_root_record(token, trusted_issuers).map_err(
        |error| match error {
            CoreError::InvalidSignature(_) | CoreError::InvalidPublicKey(_) => {
                AggregateFamilyRootStoreError::Authentication(error.to_string())
            }
            _ => AggregateFamilyRootStoreError::InvalidRecord(error.to_string()),
        },
    )?;

    let canonical_token = canonical_json_bytes(token).map_err(|error| {
        AggregateFamilyRootStoreError::InvalidRecord(format!(
            "root token canonicalization failed: {error}"
        ))
    })?;
    if canonical_token.len() > MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES {
        return Err(AggregateFamilyRootStoreError::InvalidRecord(format!(
            "root token exceeds the {MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES}-byte bound"
        )));
    }
    let canonical_token_json = String::from_utf8(canonical_token.clone()).map_err(|error| {
        AggregateFamilyRootStoreError::InvalidRecord(format!(
            "root token canonical JSON is not UTF-8: {error}"
        ))
    })?;
    let root_scope_hash = scope_hash(&token.scope).map_err(|error| {
        AggregateFamilyRootStoreError::InvalidRecord(format!("root scope hashing failed: {error}"))
    })?;

    let (root_kind, family_binding_digest, family_owner, family_max_invocations) = match &resolution
    {
        AggregateFamilyRootResolution::LegacyUnbound(_) => {
            (StoredRootKind::LegacyUnbound, None, None, None)
        }
        AggregateFamilyRootResolution::FamilyBound(verified) => (
            StoredRootKind::FamilyBound,
            Some(verified.root_binding_digest().to_string()),
            Some(verified.family_owner().to_string()),
            Some(i64::from(verified.max_invocations())),
        ),
        _ => {
            return Err(AggregateFamilyRootStoreError::InvalidRecord(
                "aggregate root verifier returned an unsupported resolution".to_string(),
            ));
        }
    };

    Ok(AuthenticatedRoot {
        record: RootRecord {
            root_capability_id: token.id.clone(),
            root_kind,
            canonical_token_json,
            token_digest: aggregate_family_root_token_digest(&canonical_token),
            issuer_key: token.issuer.to_hex(),
            subject_key: token.subject.to_hex(),
            root_scope_hash,
            issued_at,
            expires_at,
            family_binding_digest,
            family_owner,
            family_max_invocations,
            recorded_at,
        },
        resolution,
    })
}

fn stored_sequence_u64(value: i64, field: &str) -> Result<u64, AggregateFamilyRootStoreError> {
    u64::try_from(value)
        .map_err(|_| AggregateFamilyRootStoreError::Corrupt(format!("{field} is negative")))
}

fn authenticate_replication_root(
    record: &StoredAggregateFamilyRoot,
    trusted_issuers: &[PublicKey],
    recorded_at: u64,
) -> Result<AuthenticatedRoot, AggregateFamilyRootStoreError> {
    if record.canonical_token_json.len() > MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES {
        return Err(AggregateFamilyRootStoreError::InvalidRecord(format!(
            "replicated root token exceeds the {MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES}-byte bound"
        )));
    }
    let strict_canonical =
        canonical_json_bytes_from_str(&record.canonical_token_json).map_err(|error| {
            AggregateFamilyRootStoreError::InvalidRecord(format!(
                "replicated root token is not strict I-JSON: {error}"
            ))
        })?;
    if strict_canonical.as_slice() != record.canonical_token_json.as_bytes() {
        return Err(AggregateFamilyRootStoreError::InvalidRecord(
            "replicated root token JSON is not canonical".to_string(),
        ));
    }
    if aggregate_family_root_token_digest(&strict_canonical) != record.token_digest {
        return Err(AggregateFamilyRootStoreError::InvalidRecord(
            "replicated root token digest mismatch".to_string(),
        ));
    }
    let token: CapabilityToken = serde_json::from_slice(&strict_canonical).map_err(|error| {
        AggregateFamilyRootStoreError::InvalidRecord(format!(
            "replicated root token cannot be decoded: {error}"
        ))
    })?;
    let typed_canonical = canonical_json_bytes(&token).map_err(|error| {
        AggregateFamilyRootStoreError::InvalidRecord(format!(
            "replicated root token cannot be recanonicalized: {error}"
        ))
    })?;
    if typed_canonical != strict_canonical {
        return Err(AggregateFamilyRootStoreError::InvalidRecord(
            "replicated root token contains non-schema or non-canonical fields".to_string(),
        ));
    }
    authenticate_root(&token, trusted_issuers, recorded_at)
}

fn record_authenticated_roots(
    connection: &mut Connection,
    roots: &[AuthenticatedRoot],
) -> Result<Vec<AggregateFamilyRootRecordStatus>, AggregateFamilyRootStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_to_store_error)?;
    validate_schema_integrity(&transaction).map_err(schema_integrity_to_store_error)?;

    let statuses = apply_authenticated_roots(&transaction, roots)?;

    transaction.commit().map_err(sqlite_to_store_error)?;
    Ok(statuses)
}

fn apply_authenticated_roots(
    connection: &Connection,
    roots: &[AuthenticatedRoot],
) -> Result<Vec<AggregateFamilyRootRecordStatus>, AggregateFamilyRootStoreError> {
    let mut statuses = Vec::with_capacity(roots.len());
    for root in roots {
        let existing = load_root_record(connection, &root.record.root_capability_id)
            .map_err(sqlite_to_store_error)?;
        if let Some(existing) = existing {
            let existing = validate_stored_root(existing)?;
            if existing.record.canonical_token_json == root.record.canonical_token_json {
                statuses.push(AggregateFamilyRootRecordStatus::AlreadyPresent);
                continue;
            }
            return Err(AggregateFamilyRootStoreError::Conflict {
                root_capability_id: root.record.root_capability_id.clone(),
            });
        }

        insert_root_record(connection, &root.record).map_err(sqlite_to_store_error)?;
        statuses.push(AggregateFamilyRootRecordStatus::Inserted);
    }

    Ok(statuses)
}

fn record_issued_root(
    connection: &mut Connection,
    root: &AuthenticatedRoot,
    lineage: &IssuedRootLineage,
) -> Result<AggregateFamilyRootRecordStatus, AggregateFamilyRootStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_to_store_error)?;
    validate_schema_integrity(&transaction).map_err(schema_integrity_to_store_error)?;

    let mut statuses = apply_authenticated_roots(&transaction, core::slice::from_ref(root))?;
    let status = statuses.pop().ok_or_else(|| {
        AggregateFamilyRootStoreError::Corrupt(
            "issued root registration returned no status".to_string(),
        )
    })?;
    record_issued_root_lineage(&transaction, lineage)?;

    transaction.commit().map_err(sqlite_to_store_error)?;
    Ok(status)
}

fn issued_root_lineage(
    token: &CapabilityToken,
    root: &AuthenticatedRoot,
) -> Result<IssuedRootLineage, AggregateFamilyRootStoreError> {
    let grants_json = serde_json::to_string(&token.scope).map_err(|error| {
        AggregateFamilyRootStoreError::InvalidRecord(format!(
            "root lineage scope serialization failed: {error}"
        ))
    })?;

    Ok(IssuedRootLineage {
        capability_id: root.record.root_capability_id.clone(),
        subject_key: root.record.subject_key.clone(),
        issuer_key: root.record.issuer_key.clone(),
        issued_at: root.record.issued_at,
        expires_at: root.record.expires_at,
        grants_json,
        delegation_depth: 0,
        parent_capability_id: None,
    })
}

fn record_issued_root_lineage(
    connection: &Connection,
    expected: &IssuedRootLineage,
) -> Result<(), AggregateFamilyRootStoreError> {
    if let Some(existing) = load_issued_root_lineage(connection, &expected.capability_id)? {
        if existing == *expected {
            return Ok(());
        }
        return Err(AggregateFamilyRootStoreError::Conflict {
            root_capability_id: expected.capability_id.clone(),
        });
    }

    connection
        .execute(
            r#"
            INSERT INTO capability_lineage (
                capability_id, subject_key, issuer_key, issued_at, expires_at,
                grants_json, delegation_depth, parent_capability_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                expected.capability_id,
                expected.subject_key,
                expected.issuer_key,
                expected.issued_at,
                expected.expires_at,
                expected.grants_json,
                expected.delegation_depth,
                expected.parent_capability_id,
            ],
        )
        .map_err(sqlite_to_store_error)?;

    match load_issued_root_lineage(connection, &expected.capability_id)? {
        Some(inserted) if inserted == *expected => Ok(()),
        Some(_) => Err(AggregateFamilyRootStoreError::Conflict {
            root_capability_id: expected.capability_id.clone(),
        }),
        None => Err(AggregateFamilyRootStoreError::Corrupt(
            "issued root lineage insert did not create a durable row".to_string(),
        )),
    }
}

fn load_issued_root_lineage(
    connection: &Connection,
    capability_id: &str,
) -> Result<Option<IssuedRootLineage>, AggregateFamilyRootStoreError> {
    let stored = connection
        .query_row(
            r#"
            SELECT
                capability_id, subject_key, issuer_key, issued_at, expires_at,
                grants_json, delegation_depth, parent_capability_id
            FROM capability_lineage
            WHERE capability_id = ?1 COLLATE BINARY
            "#,
            params![capability_id],
            |row| {
                Ok(IssuedRootLineage {
                    capability_id: row.get(0)?,
                    subject_key: row.get(1)?,
                    issuer_key: row.get(2)?,
                    issued_at: row.get(3)?,
                    expires_at: row.get(4)?,
                    grants_json: row.get(5)?,
                    delegation_depth: row.get(6)?,
                    parent_capability_id: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_to_store_error)?;

    if let Some(stored) = stored.as_ref() {
        if stored.issued_at < 0 || stored.expires_at < 0 || stored.delegation_depth < 0 {
            return Err(AggregateFamilyRootStoreError::Corrupt(format!(
                "capability lineage for {} contains a negative integer",
                stored.capability_id
            )));
        }
    }
    Ok(stored)
}

fn insert_root_record(connection: &Connection, record: &RootRecord) -> Result<(), rusqlite::Error> {
    connection.execute(
        r#"
        INSERT INTO chio_aggregate_family_roots (
            root_capability_id, root_kind, canonical_token_json, token_digest,
            issuer_key, subject_key, root_scope_hash, issued_at, expires_at,
            family_binding_digest, family_owner, family_max_invocations, recorded_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
        )
        "#,
        params![
            record.root_capability_id,
            record.root_kind.as_str(),
            record.canonical_token_json,
            record.token_digest,
            record.issuer_key,
            record.subject_key,
            record.root_scope_hash,
            record.issued_at,
            record.expires_at,
            record.family_binding_digest,
            record.family_owner,
            record.family_max_invocations,
            record.recorded_at,
        ],
    )?;
    Ok(())
}

fn load_root_record(
    connection: &Connection,
    root_capability_id: &str,
) -> Result<Option<RootRecord>, rusqlite::Error> {
    let encoded_len = connection
        .query_row(
            "SELECT length(CAST(canonical_token_json AS BLOB)) \
             FROM chio_aggregate_family_roots \
             WHERE root_capability_id = ?1 COLLATE BINARY",
            params![root_capability_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(encoded_len) = encoded_len else {
        return Ok(None);
    };
    let maximum = i64::try_from(MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    if encoded_len < 0 || encoded_len > maximum {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            format!(
                "stored aggregate family-root token has {encoded_len} bytes, maximum is {maximum}"
            )
            .into(),
        ));
    }
    connection
        .query_row(
            r#"
            SELECT
                root_capability_id, root_kind, canonical_token_json, token_digest,
                issuer_key, subject_key, root_scope_hash, issued_at, expires_at,
                family_binding_digest, family_owner, family_max_invocations, recorded_at
            FROM chio_aggregate_family_roots
            WHERE root_capability_id = ?1 COLLATE BINARY
            "#,
            params![root_capability_id],
            |row| {
                let root_kind: String = row.get(1)?;
                let root_kind = match root_kind.as_str() {
                    "legacy_unbound" => StoredRootKind::LegacyUnbound,
                    "family_bound" => StoredRootKind::FamilyBound,
                    _ => {
                        return Err(rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            format!("unknown aggregate family-root kind: {root_kind}").into(),
                        ));
                    }
                };
                Ok(RootRecord {
                    root_capability_id: row.get(0)?,
                    root_kind,
                    canonical_token_json: row.get(2)?,
                    token_digest: row.get(3)?,
                    issuer_key: row.get(4)?,
                    subject_key: row.get(5)?,
                    root_scope_hash: row.get(6)?,
                    issued_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    family_binding_digest: row.get(9)?,
                    family_owner: row.get(10)?,
                    family_max_invocations: row.get(11)?,
                    recorded_at: row.get(12)?,
                })
            },
        )
        .optional()
}

fn validate_stored_root(
    stored: RootRecord,
) -> Result<AuthenticatedRoot, AggregateFamilyRootStoreError> {
    if stored.recorded_at < 0 {
        return Err(AggregateFamilyRootStoreError::Corrupt(
            "stored recorded_at is negative".to_string(),
        ));
    }
    if stored.canonical_token_json.len() > MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES {
        return Err(AggregateFamilyRootStoreError::Corrupt(format!(
            "stored root token exceeds the {MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES}-byte bound"
        )));
    }
    let strict_canonical =
        canonical_json_bytes_from_str(&stored.canonical_token_json).map_err(|error| {
            AggregateFamilyRootStoreError::Corrupt(format!(
                "stored root token is not strict I-JSON: {error}"
            ))
        })?;
    if strict_canonical.as_slice() != stored.canonical_token_json.as_bytes() {
        return Err(AggregateFamilyRootStoreError::Corrupt(
            "stored root token JSON is not canonical".to_string(),
        ));
    }
    let token: CapabilityToken = serde_json::from_slice(&strict_canonical).map_err(|error| {
        AggregateFamilyRootStoreError::Corrupt(format!(
            "stored root token cannot be decoded: {error}"
        ))
    })?;
    let typed_canonical = canonical_json_bytes(&token).map_err(|error| {
        AggregateFamilyRootStoreError::Corrupt(format!(
            "stored root token cannot be recanonicalized: {error}"
        ))
    })?;
    if typed_canonical != strict_canonical {
        return Err(AggregateFamilyRootStoreError::Corrupt(
            "stored root token contains non-schema or non-canonical fields".to_string(),
        ));
    }
    if stored.token_digest != aggregate_family_root_token_digest(&strict_canonical) {
        return Err(AggregateFamilyRootStoreError::Corrupt(
            "stored root token digest mismatch".to_string(),
        ));
    }
    if stored.issuer_key != token.issuer.to_hex() {
        return Err(AggregateFamilyRootStoreError::Corrupt(
            "stored root issuer projection mismatch".to_string(),
        ));
    }

    let recorded_at = u64::try_from(stored.recorded_at).map_err(|_| {
        AggregateFamilyRootStoreError::Corrupt(
            "stored recorded_at is outside the supported range".to_string(),
        )
    })?;
    let authenticated =
        authenticate_root(&token, core::slice::from_ref(&token.issuer), recorded_at)
            .map_err(authentication_to_corrupt)?;
    if authenticated.record != stored {
        return Err(AggregateFamilyRootStoreError::Corrupt(
            "stored root projection does not match authenticated token".to_string(),
        ));
    }
    Ok(authenticated)
}

fn sqlite_record_i64(value: u64, field: &str) -> Result<i64, AggregateFamilyRootStoreError> {
    i64::try_from(value).map_err(|_| {
        AggregateFamilyRootStoreError::InvalidRecord(format!(
            "{field} exceeds the SQLite INTEGER range"
        ))
    })
}

/// Domain-separated digest of one exact canonical aggregate-root token.
pub fn aggregate_family_root_token_digest(canonical_token: &[u8]) -> String {
    let mut bytes =
        Vec::with_capacity(AGGREGATE_FAMILY_ROOT_TOKEN_DIGEST_DOMAIN.len() + canonical_token.len());
    bytes.extend_from_slice(AGGREGATE_FAMILY_ROOT_TOKEN_DIGEST_DOMAIN.as_bytes());
    bytes.extend_from_slice(canonical_token);
    sha256_hex(&bytes)
}

fn validate_schema_integrity(connection: &Connection) -> Result<(), SchemaIntegrityError> {
    let module_version = read_module_schema_version(connection)?;
    if module_version != Some(AGGREGATE_FAMILY_ROOT_SCHEMA_VERSION) {
        return Err(SchemaIntegrityError::Corrupt(format!(
            "aggregate family-root module version is {module_version:?}, expected {AGGREGATE_FAMILY_ROOT_SCHEMA_VERSION}"
        )));
    }

    validate_schema_integrity_without_module_version(connection)
}

fn validate_schema_integrity_without_module_version(
    connection: &Connection,
) -> Result<(), SchemaIntegrityError> {
    for (object_type, object_name, expected_sql) in AGGREGATE_FAMILY_ROOT_SCHEMA_OBJECTS {
        let actual_sql =
            sqlite_object_sql(connection, object_type, object_name)?.ok_or_else(|| {
                SchemaIntegrityError::Corrupt(format!(
                    "required {object_type} {object_name} is missing"
                ))
            })?;
        if normalize_sql(&actual_sql) != normalize_sql(expected_sql) {
            return Err(SchemaIntegrityError::Corrupt(format!(
                "required {object_type} {object_name} does not match the authority schema"
            )));
        }
    }

    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_master \
         WHERE type = 'trigger' \
           AND tbl_name IN ('chio_aggregate_family_root_schema', 'chio_aggregate_family_roots') \
         ORDER BY name ASC",
    )?;
    let actual_triggers = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected_triggers = AGGREGATE_FAMILY_ROOT_SCHEMA_OBJECTS
        .iter()
        .filter_map(|(object_type, object_name, _)| {
            (*object_type == "trigger").then_some((*object_name).to_string())
        })
        .collect::<Vec<_>>();
    expected_triggers.sort_unstable();
    if actual_triggers != expected_triggers {
        return Err(SchemaIntegrityError::Corrupt(
            "aggregate family-root tables have an unexpected trigger set".to_string(),
        ));
    }
    drop(statement);

    let sentinel = connection
        .query_row(
            "SELECT singleton, schema_version, schema_fingerprint \
             FROM chio_aggregate_family_root_schema",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match sentinel {
        Some((1, AGGREGATE_FAMILY_ROOT_SCHEMA_VERSION, fingerprint))
            if fingerprint == AGGREGATE_FAMILY_ROOT_SCHEMA_FINGERPRINT => {}
        Some(_) => {
            return Err(SchemaIntegrityError::Corrupt(
                "aggregate family-root schema sentinel is invalid".to_string(),
            ));
        }
        None => {
            return Err(SchemaIntegrityError::Corrupt(
                "aggregate family-root schema sentinel is missing".to_string(),
            ));
        }
    }

    let sentinel_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_aggregate_family_root_schema",
        [],
        |row| row.get(0),
    )?;
    if sentinel_count != 1 {
        return Err(SchemaIntegrityError::Corrupt(
            "aggregate family-root schema sentinel cardinality is invalid".to_string(),
        ));
    }
    Ok(())
}

fn read_module_schema_version(connection: &Connection) -> Result<Option<i64>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT version FROM chio_module_schema_version WHERE module = ?1",
            params![AGGREGATE_FAMILY_ROOT_MODULE_NAME],
            |row| row.get(0),
        )
        .optional()
}

fn stamp_module_schema_version(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO chio_module_schema_version (module, version) VALUES (?1, ?2) \
         ON CONFLICT(module) DO UPDATE SET version = excluded.version",
        params![
            AGGREGATE_FAMILY_ROOT_MODULE_NAME,
            AGGREGATE_FAMILY_ROOT_SCHEMA_VERSION
        ],
    )?;
    Ok(())
}

fn sqlite_object_sql(
    connection: &Connection,
    object_type: &str,
    object_name: &str,
) -> Result<Option<String>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            params![object_type, object_name],
            |row| row.get(0),
        )
        .optional()
}

fn normalize_sql(sql: &str) -> String {
    sql.trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn schema_integrity_to_receipt_error(error: SchemaIntegrityError) -> ReceiptStoreError {
    match error {
        SchemaIntegrityError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
        SchemaIntegrityError::Corrupt(reason) => ReceiptStoreError::Conflict(reason),
    }
}

fn schema_integrity_to_store_error(error: SchemaIntegrityError) -> AggregateFamilyRootStoreError {
    match error {
        SchemaIntegrityError::Sqlite(error) => sqlite_to_store_error(error),
        SchemaIntegrityError::Corrupt(reason) => AggregateFamilyRootStoreError::Corrupt(reason),
    }
}

fn schema_integrity_to_resolution_error(
    error: SchemaIntegrityError,
) -> AggregateFamilyRootResolutionError {
    match error {
        SchemaIntegrityError::Sqlite(error) => sqlite_to_resolution_error(error),
        SchemaIntegrityError::Corrupt(reason) => {
            AggregateFamilyRootResolutionError::Corrupt(reason)
        }
    }
}

fn authentication_to_corrupt(
    error: AggregateFamilyRootStoreError,
) -> AggregateFamilyRootStoreError {
    AggregateFamilyRootStoreError::Corrupt(error.to_string())
}

fn receipt_store_unavailable(error: ReceiptStoreError) -> AggregateFamilyRootStoreError {
    AggregateFamilyRootStoreError::Unavailable(error.to_string())
}

fn sqlite_to_store_error(error: rusqlite::Error) -> AggregateFamilyRootStoreError {
    if sqlite_error_is_corrupt(&error) {
        return AggregateFamilyRootStoreError::Corrupt(error.to_string());
    }
    match error {
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..) => {
            AggregateFamilyRootStoreError::Corrupt(error.to_string())
        }
        _ => AggregateFamilyRootStoreError::Unavailable(error.to_string()),
    }
}

fn sqlite_to_resolution_error(error: rusqlite::Error) -> AggregateFamilyRootResolutionError {
    if sqlite_error_is_corrupt(&error) {
        return AggregateFamilyRootResolutionError::Corrupt(error.to_string());
    }
    match error {
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..) => {
            AggregateFamilyRootResolutionError::Corrupt(error.to_string())
        }
        _ => AggregateFamilyRootResolutionError::Unavailable(error.to_string()),
    }
}

fn sqlite_error_is_corrupt(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(
            rusqlite::ErrorCode::DatabaseCorrupt
                | rusqlite::ErrorCode::NotADatabase
                | rusqlite::ErrorCode::SchemaChanged
                | rusqlite::ErrorCode::TypeMismatch
                | rusqlite::ErrorCode::Unknown
        )
    )
}

fn store_to_resolution_error(
    error: AggregateFamilyRootStoreError,
) -> AggregateFamilyRootResolutionError {
    match error {
        AggregateFamilyRootStoreError::Unavailable(reason) => {
            AggregateFamilyRootResolutionError::Unavailable(reason)
        }
        other => AggregateFamilyRootResolutionError::Corrupt(other.to_string()),
    }
}
