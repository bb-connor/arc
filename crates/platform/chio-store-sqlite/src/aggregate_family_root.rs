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

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use chio_core::capability::aggregate_budget::{
        issue_aggregate_family_root, verify_aggregate_invocation_authority,
        verify_direct_aggregate_family_root, AggregateFamilyRootResolution,
        AggregateFamilyRootResolutionError, AggregateFamilyRootResolver,
        AggregateInvocationAuthorityError, AggregateInvocationBudget, AggregateInvocationScope,
    };
    use chio_core::capability::attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    };
    use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
    use chio_core::capability::token::{
        CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody,
    };
    use chio_core::{Keypair, PublicKey, SigningAlgorithm};
    use rusqlite::{params, Connection};
    use tempfile::tempdir;

    use crate::SqliteReceiptStore;

    type TestResult = Result<(), Box<dyn StdError>>;

    fn delegable_scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "family-server".to_string(),
                tool_name: "family-tool".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        }
    }

    fn root_body(id: &str, issuer: PublicKey, subject: PublicKey) -> CapabilityTokenBody {
        CapabilityTokenBody {
            id: id.to_string(),
            issuer,
            subject,
            scope: delegable_scope(),
            issued_at: 1_000,
            expires_at: 2_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        }
    }

    fn family_root(
        id: &str,
        max_invocations: u32,
    ) -> Result<(Keypair, Keypair, CapabilityToken), chio_core::Error> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let token = family_root_with_keys(id, max_invocations, &issuer, &subject)?;
        Ok((issuer, subject, token))
    }

    fn family_root_with_keys(
        id: &str,
        max_invocations: u32,
        issuer: &Keypair,
        subject: &Keypair,
    ) -> Result<CapabilityToken, chio_core::Error> {
        let token = issue_aggregate_family_root(
            root_body(id, issuer.public_key(), subject.public_key()),
            max_invocations,
            issuer,
        )?;
        Ok(token)
    }

    fn legacy_root(id: &str) -> Result<(Keypair, Keypair, CapabilityToken), chio_core::Error> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let token = CapabilityToken::sign(
            root_body(id, issuer.public_key(), subject.public_key()),
            &issuer,
        )?;
        Ok((issuer, subject, token))
    }

    fn omitted_family_descendant(
        root: &CapabilityToken,
        root_subject: &Keypair,
        child_subject: &Keypair,
    ) -> Result<CapabilityToken, chio_core::Error> {
        let link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: root.id.clone(),
                delegator: root_subject.public_key(),
                delegatee: child_subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 1_100,
                scope_hash: Some(scope_hash(&root.scope)?),
                aggregate_family_preservation: None,
            },
            root_subject,
        )?;
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "family-omission-child".to_string(),
                issuer: root_subject.public_key(),
                subject: child_subject.public_key(),
                scope: root.scope.clone(),
                issued_at: 1_100,
                expires_at: 1_900,
                delegation_chain: vec![link],
                aggregate_invocation_budget: None,
            },
            root_subject,
        )
    }

    fn row_count(path: &std::path::Path) -> Result<i64, rusqlite::Error> {
        let connection = Connection::open(path)?;
        connection.query_row(
            "SELECT COUNT(*) FROM chio_aggregate_family_roots",
            [],
            |row| row.get(0),
        )
    }

    fn drop_update_guard(connection: &Connection) -> Result<(), rusqlite::Error> {
        connection.execute_batch("DROP TRIGGER chio_aggregate_family_roots_immutable_update;")
    }

    fn restore_update_guard(connection: &Connection) -> Result<(), rusqlite::Error> {
        connection.execute_batch(super::AGGREGATE_FAMILY_ROOT_UPDATE_TRIGGER_SQL)
    }

    #[test]
    fn aggregate_family_root_empty_database_is_missing_not_legacy() -> TestResult {
        let directory = tempdir()?;
        let store = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;

        assert_eq!(
            store.resolve_aggregate_family_root("never-registered"),
            Err(AggregateFamilyRootResolutionError::Missing)
        );
        Ok(())
    }

    #[test]
    fn aggregate_family_root_family_record_reopens_and_resolves() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let (issuer, _subject, token) = family_root("family-reopen", 7)?;
        {
            let store = SqliteReceiptStore::open(&path)?;
            let status =
                store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
            assert_eq!(status, super::AggregateFamilyRootRecordStatus::Inserted);
        }

        let reopened = SqliteReceiptStore::open(&path)?;
        let resolved = reopened.resolve_aggregate_family_root(&token.id)?;
        match resolved {
            AggregateFamilyRootResolution::FamilyBound(root) => {
                assert_eq!(root.root_capability_id(), token.id);
                assert_eq!(root.max_invocations(), 7);
            }
            other => panic!("expected family-bound root, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_explicit_legacy_record_reopens_and_resolves() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let (issuer, _subject, token) = legacy_root("legacy-reopen")?;
        {
            let store = SqliteReceiptStore::open(&path)?;
            store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        }

        let reopened = SqliteReceiptStore::open(&path)?;
        let resolved = reopened.resolve_aggregate_family_root(&token.id)?;
        match resolved {
            AggregateFamilyRootResolution::LegacyUnbound(root) => {
                assert_eq!(root.root_capability_id(), token.id);
                assert_eq!(root.root_subject(), &token.subject);
                assert_eq!(root.root_expires_at(), token.expires_at);
            }
            other => panic!("expected explicit legacy root, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_descendant_omission_denies_after_restart() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let (issuer, root_subject, root) = family_root("family-omission-root", 5)?;
        let child_subject = Keypair::generate();
        let descendant = omitted_family_descendant(&root, &root_subject, &child_subject)?;
        {
            let store = SqliteReceiptStore::open(&path)?;
            store.record_aggregate_family_root(&root, &[issuer.public_key()], 1_100)?;
        }

        let reopened = SqliteReceiptStore::open(&path)?;
        let error = match verify_aggregate_invocation_authority(
            &descendant,
            &[],
            &[root_subject.public_key()],
            &reopened,
        ) {
            Err(error) => error,
            Ok(_) => panic!("family omission must deny after restart"),
        };
        assert!(matches!(
            error,
            AggregateInvocationAuthorityError::Verification(
                chio_core::Error::AttenuationViolation { .. }
            )
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_identical_retry_is_already_present() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-retry", 5)?;
        let trusted = [issuer.public_key()];

        assert_eq!(
            store.record_aggregate_family_root(&token, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::Inserted
        );
        assert_eq!(
            store.record_aggregate_family_root(&token, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::AlreadyPresent
        );
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn issued_aggregate_family_root_records_exact_lineage_idempotently() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-issued-lineage", 5)?;
        let trusted = [issuer.public_key()];

        assert_eq!(
            store.record_issued_aggregate_family_root(&token, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::Inserted
        );
        assert_eq!(
            store.record_issued_aggregate_family_root(&token, &trusted, 1_200)?,
            super::AggregateFamilyRootRecordStatus::AlreadyPresent
        );

        let lineage = match store.get_lineage(&token.id)? {
            Some(lineage) => lineage,
            None => panic!("issued root lineage is missing"),
        };
        assert_eq!(lineage.capability_id, token.id);
        assert_eq!(lineage.subject_key, token.subject.to_hex());
        assert_eq!(lineage.issuer_key, token.issuer.to_hex());
        assert_eq!(lineage.issued_at, token.issued_at);
        assert_eq!(lineage.expires_at, token.expires_at);
        assert_eq!(lineage.grants_json, serde_json::to_string(&token.scope)?);
        assert_eq!(lineage.delegation_depth, 0);
        assert_eq!(lineage.parent_capability_id, None);
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn issued_aggregate_family_root_lineage_failure_rolls_back_root() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TRIGGER reject_issued_root_lineage
             BEFORE INSERT ON capability_lineage
             BEGIN
                 SELECT RAISE(ABORT, 'lineage rejected');
             END;",
        )?;
        let (issuer, _subject, token) = family_root("family-lineage-rollback", 5)?;

        let error = match store.record_issued_aggregate_family_root(
            &token,
            &[issuer.public_key()],
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("lineage rejection must fail root capture"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Unavailable(_)
        ));
        assert_eq!(row_count(&path)?, 0);
        assert!(store.get_lineage(&token.id)?.is_none());
        Ok(())
    }

    #[test]
    fn issued_aggregate_family_root_conflicting_lineage_rolls_back_root() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-lineage-conflict", 5)?;
        let conflicting_subject = Keypair::generate();
        let conflicting = CapabilityToken::sign(
            root_body(
                &token.id,
                issuer.public_key(),
                conflicting_subject.public_key(),
            ),
            &issuer,
        )?;
        store.record_capability_snapshot(&conflicting, None)?;

        let error = match store.record_issued_aggregate_family_root(
            &token,
            &[issuer.public_key()],
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("conflicting lineage must fail root capture"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { ref root_capability_id }
                if root_capability_id == &token.id
        ));
        assert_eq!(row_count(&path)?, 0);
        let lineage = match store.get_lineage(&token.id)? {
            Some(lineage) => lineage,
            None => panic!("conflicting lineage was removed"),
        };
        assert_eq!(lineage.subject_key, conflicting.subject.to_hex());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_round_trips_full_tokens_in_order() -> TestResult {
        let source_directory = tempdir()?;
        let source_path = source_directory.path().join("source.db");
        let source = SqliteReceiptStore::open(&source_path)?;
        let (family_issuer, _family_subject, family) = family_root("replicated-family-root", 5)?;
        let (legacy_issuer, _legacy_subject, legacy) = legacy_root("replicated-legacy-root")?;
        let trusted = [family_issuer.public_key(), legacy_issuer.public_key()];
        source.record_aggregate_family_root(&family, &trusted, 1_100)?;
        source.record_aggregate_family_root(&legacy, &trusted, 1_200)?;

        assert_eq!(source.max_aggregate_family_root_seq()?, 2);
        let first = source.list_aggregate_family_roots_after_seq(0, 1)?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].seq, 1);
        assert_eq!(
            serde_json::from_str::<CapabilityToken>(&first[0].canonical_token_json)?.id,
            family.id
        );
        let second = source.list_aggregate_family_roots_after_seq(first[0].seq, 8)?;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].seq, 2);
        assert_eq!(
            serde_json::from_str::<CapabilityToken>(&second[0].canonical_token_json)?.id,
            legacy.id
        );

        let mut records = first;
        records.extend(second);
        let target_directory = tempdir()?;
        let target_path = target_directory.path().join("target.db");
        {
            let target = SqliteReceiptStore::open(&target_path)?;
            assert_eq!(
                target.import_aggregate_family_roots(&records, &trusted, 1_300)?,
                vec![
                    super::AggregateFamilyRootRecordStatus::Inserted,
                    super::AggregateFamilyRootRecordStatus::Inserted,
                ]
            );
        }

        let reopened = SqliteReceiptStore::open(&target_path)?;
        assert!(matches!(
            reopened.resolve_aggregate_family_root(&family.id),
            Ok(AggregateFamilyRootResolution::FamilyBound(root))
                if root.max_invocations() == 5
        ));
        assert!(matches!(
            reopened.resolve_aggregate_family_root(&legacy.id),
            Ok(AggregateFamilyRootResolution::LegacyUnbound(_))
        ));
        let reopened_ids = reopened
            .list_aggregate_family_roots_after_seq(0, 8)?
            .into_iter()
            .map(|record| {
                serde_json::from_str::<CapabilityToken>(&record.canonical_token_json)
                    .map(|token| token.id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(reopened_ids, vec![family.id, legacy.id]);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_lookup_returns_token_and_head_from_one_snapshot() -> TestResult {
        let directory = tempdir()?;
        let store = SqliteReceiptStore::open(directory.path().join("roots.db"))?;
        let (issuer, _subject, token) = family_root("lookup-family-root", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;

        let found = store.lookup_aggregate_family_root(&token.id)?;
        assert_eq!(found.high_watermark, 1);
        let record = match found.record {
            Some(record) => record,
            None => panic!("recorded root must be returned"),
        };
        assert_eq!(record.seq, 1);
        assert_eq!(
            serde_json::from_str::<CapabilityToken>(&record.canonical_token_json)?.id,
            token.id
        );
        assert_eq!(
            record.token_digest,
            super::aggregate_family_root_token_digest(record.canonical_token_json.as_bytes())
        );

        let missing = store.lookup_aggregate_family_root("missing-root")?;
        assert_eq!(missing.high_watermark, 1);
        assert!(missing.record.is_none());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_preserves_the_exact_canonical_artifact() -> TestResult {
        let source_directory = tempdir()?;
        let source = SqliteReceiptStore::open(source_directory.path().join("source.db"))?;
        let (issuer, _subject, token) = family_root("replication-canonical-root", 5)?;
        source.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let exported = source.list_aggregate_family_roots_after_seq(0, 1)?;
        let original = match exported.first() {
            Some(record) => record,
            None => panic!("source root must be exported"),
        };

        let mut value = serde_json::to_value(&token)?;
        let object = match value.as_object_mut() {
            Some(object) => object,
            None => panic!("capability token must serialize as an object"),
        };
        object.insert("unknownRootField".to_string(), serde_json::json!(true));
        let canonical_with_unknown = chio_core::canonicalize(&value)?;
        let noncanonical = serde_json::to_string_pretty(&token)?;
        let duplicate_id = format!(
            "{{\"id\":\"duplicate\",{}",
            original
                .canonical_token_json
                .strip_prefix('{')
                .unwrap_or(&original.canonical_token_json)
        );
        let cases = [
            super::StoredAggregateFamilyRoot {
                seq: 1,
                token_digest: super::aggregate_family_root_token_digest(noncanonical.as_bytes()),
                canonical_token_json: noncanonical,
            },
            super::StoredAggregateFamilyRoot {
                seq: 1,
                token_digest: super::aggregate_family_root_token_digest(
                    canonical_with_unknown.as_bytes(),
                ),
                canonical_token_json: canonical_with_unknown,
            },
            super::StoredAggregateFamilyRoot {
                seq: 1,
                token_digest: super::aggregate_family_root_token_digest(duplicate_id.as_bytes()),
                canonical_token_json: duplicate_id,
            },
            super::StoredAggregateFamilyRoot {
                seq: 1,
                token_digest: "0".repeat(64),
                canonical_token_json: original.canonical_token_json.clone(),
            },
        ];

        let target_directory = tempdir()?;
        let target_path = target_directory.path().join("target.db");
        let target = SqliteReceiptStore::open(&target_path)?;
        for record in cases {
            assert!(matches!(
                target.import_aggregate_family_roots(&[record], &[issuer.public_key()], 1_200),
                Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
            ));
            assert_eq!(row_count(&target_path)?, 0);
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_rejects_unrepresentable_pagination() -> TestResult {
        let directory = tempdir()?;
        let store = SqliteReceiptStore::open(directory.path().join("roots.db"))?;

        assert!(matches!(
            store.list_aggregate_family_roots_after_seq(u64::MAX, 1),
            Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
        ));
        assert!(matches!(
            store.list_aggregate_family_roots_after_seq(0, usize::MAX),
            Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_authenticates_batch_before_mutation() -> TestResult {
        let source_directory = tempdir()?;
        let source = SqliteReceiptStore::open(source_directory.path().join("source.db"))?;
        let (trusted_issuer, _trusted_subject, trusted_root) =
            family_root("replication-trusted-root", 5)?;
        let (untrusted_issuer, _untrusted_subject, untrusted_root) =
            family_root("replication-untrusted-root", 6)?;
        source.record_aggregate_family_root(
            &trusted_root,
            &[trusted_issuer.public_key()],
            1_100,
        )?;
        source.record_aggregate_family_root(
            &untrusted_root,
            &[untrusted_issuer.public_key()],
            1_200,
        )?;
        let records = source.list_aggregate_family_roots_after_seq(0, 8)?;

        let target_directory = tempdir()?;
        let target_path = target_directory.path().join("target.db");
        let target = SqliteReceiptStore::open(&target_path)?;
        let error = match target.import_aggregate_family_roots(
            &records,
            &[trusted_issuer.public_key()],
            1_300,
        ) {
            Err(error) => error,
            Ok(_) => panic!("untrusted replicated root must fail the complete batch"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Authentication(_)
        ));
        assert_eq!(row_count(&target_path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_replication_conflict_retains_follower_state() -> TestResult {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let original = family_root_with_keys("replication-conflict", 5, &issuer, &subject)?;
        let conflict = family_root_with_keys("replication-conflict", 6, &issuer, &subject)?;

        let source_directory = tempdir()?;
        let source = SqliteReceiptStore::open(source_directory.path().join("source.db"))?;
        source.record_aggregate_family_root(&conflict, &[issuer.public_key()], 1_200)?;
        let records = source.list_aggregate_family_roots_after_seq(0, 8)?;

        let target_directory = tempdir()?;
        let target = SqliteReceiptStore::open(target_directory.path().join("target.db"))?;
        target.record_aggregate_family_root(&original, &[issuer.public_key()], 1_100)?;
        let error =
            match target.import_aggregate_family_roots(&records, &[issuer.public_key()], 1_300) {
                Err(error) => error,
                Ok(_) => panic!("conflicting replicated root must fail"),
            };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { .. }
        ));
        assert!(matches!(
            target.resolve_aggregate_family_root(&original.id),
            Ok(AggregateFamilyRootResolution::FamilyBound(root))
                if root.max_invocations() == 5
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_explicit_default_algorithm_is_canonical_retry() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-default-algorithm", 5)?;
        let mut explicit_default = token.clone();
        explicit_default.algorithm = Some(SigningAlgorithm::Ed25519);
        let trusted = [issuer.public_key()];

        assert_eq!(
            store.record_aggregate_family_root(&token, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::Inserted
        );
        assert_eq!(
            store.record_aggregate_family_root(&explicit_default, &trusted, 1_100)?,
            super::AggregateFamilyRootRecordStatus::AlreadyPresent
        );
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_conflicting_valid_max_retains_original() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let original = family_root_with_keys("family-conflict", 5, &issuer, &subject)?;
        let conflict = family_root_with_keys("family-conflict", 6, &issuer, &subject)?;
        let trusted = [issuer.public_key()];
        store.record_aggregate_family_root(&original, &trusted, 1_100)?;

        let error = match store.record_aggregate_family_root(&conflict, &trusted, 1_100) {
            Err(error) => error,
            Ok(_) => panic!("changed maximum must conflict"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { ref root_capability_id }
                if root_capability_id == "family-conflict"
        ));
        match store.resolve_aggregate_family_root("family-conflict")? {
            AggregateFamilyRootResolution::FamilyBound(root) => {
                assert_eq!(root.max_invocations(), 5);
            }
            other => panic!("expected original family root, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_two_store_handles_race_first_writer() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let first_store = SqliteReceiptStore::open(&path)?;
        let second_store = SqliteReceiptStore::open(&path)?;
        let (first_issuer, _first_subject, first_token) = family_root("family-race", 5)?;
        let (second_issuer, _second_subject, second_token) = family_root("family-race", 6)?;
        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = Arc::clone(&barrier);
        let second_barrier = Arc::clone(&barrier);
        let first_key = first_issuer.public_key();
        let second_key = second_issuer.public_key();
        let first = thread::spawn(move || {
            first_barrier.wait();
            first_store.record_aggregate_family_root(&first_token, &[first_key], 1_100)
        });
        let second = thread::spawn(move || {
            second_barrier.wait();
            second_store.record_aggregate_family_root(&second_token, &[second_key], 1_100)
        });
        let first_result = match first.join() {
            Ok(result) => result,
            Err(_) => panic!("first aggregate family-root writer panicked"),
        };
        let second_result = match second.join() {
            Ok(result) => result,
            Err(_) => panic!("second aggregate family-root writer panicked"),
        };
        assert!(matches!(
            (first_result, second_result),
            (
                Ok(super::AggregateFamilyRootRecordStatus::Inserted),
                Err(super::AggregateFamilyRootStoreError::Conflict { .. })
            ) | (
                Err(super::AggregateFamilyRootStoreError::Conflict { .. }),
                Ok(super::AggregateFamilyRootRecordStatus::Inserted)
            )
        ));
        assert_eq!(row_count(&path)?, 1);
        let resolver = SqliteReceiptStore::open(&path)?;
        match resolver.resolve_aggregate_family_root("family-race")? {
            AggregateFamilyRootResolution::FamilyBound(root) => {
                assert!(matches!(root.max_invocations(), 5 | 6));
            }
            other => panic!("expected the immutable race winner, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn aggregate_family_root_insert_or_replace_cannot_bypass_immutability() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-replace-guard", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;

        let replaced = connection.execute(
            r#"
            INSERT OR REPLACE INTO chio_aggregate_family_roots (
                seq, root_capability_id, root_kind, canonical_token_json,
                token_digest, issuer_key, subject_key, root_scope_hash,
                issued_at, expires_at, family_binding_digest, family_owner,
                family_max_invocations, recorded_at
            )
            SELECT
                seq, root_capability_id, root_kind, canonical_token_json,
                token_digest, issuer_key, subject_key, root_scope_hash,
                issued_at, expires_at, family_binding_digest, family_owner,
                family_max_invocations, recorded_at + 1
            FROM chio_aggregate_family_roots
            WHERE root_capability_id = ?1
            "#,
            params![token.id],
        );
        assert!(replaced.is_err());
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_update_and_delete_triggers_are_immutable() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-immutable", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;

        assert!(connection
            .execute(
                "UPDATE chio_aggregate_family_roots SET recorded_at = 1200 WHERE root_capability_id = ?1",
                params![token.id],
            )
            .is_err());
        assert!(connection
            .execute(
                "DELETE FROM chio_aggregate_family_roots WHERE root_capability_id = ?1",
                params![token.id],
            )
            .is_err());
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_untrusted_signer_rejects_before_mutation() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (_issuer, _subject, token) = family_root("family-untrusted", 5)?;
        let untrusted = Keypair::generate();

        let error =
            match store.record_aggregate_family_root(&token, &[untrusted.public_key()], 1_100) {
                Err(error) => error,
                Ok(_) => panic!("untrusted signer must reject"),
            };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Authentication(_)
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_algorithm_envelope_mismatch_rejects_before_mutation() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, mut token) = legacy_root("legacy-algorithm-mismatch")?;
        token.algorithm = Some(SigningAlgorithm::P256);

        let error = match store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)
        {
            Err(error) => error,
            Ok(_) => panic!("unsigned algorithm envelope mismatch must reject"),
        };

        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Authentication(_)
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_batch_conflict_is_all_or_nothing() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let original = family_root_with_keys("family-batch-existing", 5, &issuer, &subject)?;
        let conflict = family_root_with_keys("family-batch-existing", 6, &issuer, &subject)?;
        let (new_issuer, _new_subject, new_root) = family_root("family-batch-new", 4)?;
        let trusted = [issuer.public_key(), new_issuer.public_key()];
        store.record_aggregate_family_root(&original, &trusted, 1_100)?;

        let error = match store.record_aggregate_family_roots(
            &[new_root.clone(), conflict],
            &trusted,
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("batch conflict must roll back every insert"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { .. }
        ));
        assert_eq!(
            store.resolve_aggregate_family_root(&new_root.id),
            Err(AggregateFamilyRootResolutionError::Missing)
        );
        assert_eq!(row_count(&path)?, 1);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_batch_authenticates_all_before_mutation() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (trusted_issuer, _trusted_subject, trusted_root) =
            family_root("family-batch-trusted", 4)?;
        let (_untrusted_issuer, _untrusted_subject, untrusted_root) =
            family_root("family-batch-untrusted", 4)?;

        let error = match store.record_aggregate_family_roots(
            &[trusted_root, untrusted_root],
            &[trusted_issuer.public_key()],
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("untrusted batch member must reject before the write transaction"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Authentication(_)
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_batch_conflicting_duplicate_ids_roll_back() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let first = family_root_with_keys("family-batch-duplicate", 5, &issuer, &subject)?;
        let second = family_root_with_keys("family-batch-duplicate", 6, &issuer, &subject)?;

        let error = match store.record_aggregate_family_roots(
            &[first, second],
            &[issuer.public_key()],
            1_100,
        ) {
            Err(error) => error,
            Ok(_) => panic!("conflicting duplicate IDs in one batch must roll back"),
        };
        assert!(matches!(
            error,
            super::AggregateFamilyRootStoreError::Conflict { .. }
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_malformed_canonical_json_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-malformed", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET canonical_token_json = '{' WHERE root_capability_id = ?1",
            params![token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_noncanonical_json_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-noncanonical", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let noncanonical = serde_json::to_string_pretty(&token)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET canonical_token_json = ?1 WHERE root_capability_id = ?2",
            params![noncanonical, token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_canonical_unknown_token_field_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-unknown-field", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let mut value = serde_json::to_value(&token)?;
        let object = match value.as_object_mut() {
            Some(object) => object,
            None => panic!("capability token must serialize as an object"),
        };
        object.insert("unknownRootField".to_string(), serde_json::json!(true));
        let canonical_with_unknown = chio_core::canonicalize(&value)?;
        let matching_digest =
            super::aggregate_family_root_token_digest(canonical_with_unknown.as_bytes());
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET canonical_token_json = ?1, token_digest = ?2 WHERE root_capability_id = ?3",
            params![canonical_with_unknown, matching_digest, token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_explicit_default_algorithm_row_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-explicit-default-row", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let mut value = serde_json::to_value(&token)?;
        let object = match value.as_object_mut() {
            Some(object) => object,
            None => panic!("capability token must serialize as an object"),
        };
        object.insert("algorithm".to_string(), serde_json::json!("ed25519"));
        let explicit_default = chio_core::canonicalize(&value)?;
        let matching_digest =
            super::aggregate_family_root_token_digest(explicit_default.as_bytes());
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET canonical_token_json = ?1, token_digest = ?2 WHERE root_capability_id = ?3",
            params![explicit_default, matching_digest, token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_token_digest_mismatch_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-digest-corrupt", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET token_digest = ?1 WHERE root_capability_id = ?2",
            params!["0".repeat(64), token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_projection_column_mismatch_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-column-corrupt", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET subject_key = issuer_key WHERE root_capability_id = ?1",
            params![token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_same_token_corrupt_projection_is_not_idempotent() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-corrupt-retry", 5)?;
        let trusted = [issuer.public_key()];
        store.record_aggregate_family_root(&token, &trusted, 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET subject_key = issuer_key WHERE root_capability_id = ?1",
            params![token.id],
        )?;
        restore_update_guard(&connection)?;

        assert!(matches!(
            store.record_aggregate_family_root(&token, &trusted, 1_100),
            Err(super::AggregateFamilyRootStoreError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_kind_mismatch_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let (issuer, _subject, token) = family_root("family-kind-corrupt", 5)?;
        store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute(
            "UPDATE chio_aggregate_family_roots SET root_kind = 'legacy_unbound', family_binding_digest = NULL, family_owner = NULL, family_max_invocations = NULL WHERE root_capability_id = ?1",
            params![token.id],
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root(&token.id),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_invalid_time_shape_and_integer_overflow_do_not_mutate() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let mut invalid_time_body = root_body(
            "legacy-invalid-time",
            issuer.public_key(),
            subject.public_key(),
        );
        invalid_time_body.issued_at = 2_000;
        invalid_time_body.expires_at = 2_000;
        let invalid_time = CapabilityToken::sign(invalid_time_body, &issuer)?;
        let mut overflow_body = root_body(
            "legacy-overflow-time",
            issuer.public_key(),
            subject.public_key(),
        );
        overflow_body.issued_at = i64::MAX as u64 + 1;
        overflow_body.expires_at = i64::MAX as u64 + 2;
        let overflow = CapabilityToken::sign(overflow_body, &issuer)?;
        let trusted = [issuer.public_key()];

        for candidate in [&invalid_time, &overflow] {
            assert!(matches!(
                store.record_aggregate_family_root(candidate, &trusted, 1_100),
                Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
            ));
        }
        let (valid_issuer, _valid_subject, valid) = legacy_root("legacy-recorded-at-overflow")?;
        assert!(matches!(
            store.record_aggregate_family_root(&valid, &[valid_issuer.public_key()], u64::MAX),
            Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
        ));
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_rejects_nonroot_shapes() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let nondelegable = CapabilityToken::sign(
            CapabilityTokenBody {
                scope: ChioScope::default(),
                ..root_body(
                    "plain-nondelegable",
                    issuer.public_key(),
                    subject.public_key(),
                )
            },
            &issuer,
        )?;
        let capability_scoped = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "capability-scoped-not-root".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_000,
                expires_at: 2_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: Some(AggregateInvocationBudget {
                    scope: AggregateInvocationScope::Capability,
                    max_invocations: 5,
                    root_binding: None,
                }),
            },
            &issuer,
        )?;
        let nondelegable_family = issue_aggregate_family_root(
            CapabilityTokenBody {
                id: "family-nondelegable".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_000,
                expires_at: 2_000,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            5,
            &issuer,
        )?;
        let delegable_family =
            family_root_with_keys("delegated-token-parent", 5, &issuer, &subject)?;
        let child_subject = Keypair::generate();
        let delegated = omitted_family_descendant(&delegable_family, &subject, &child_subject)?;
        let legacy_proof = AttenuationProof {
            parent_scope_hash: scope_hash(&delegable_family.scope)?,
            child_scope_hash: scope_hash(&delegable_family.scope)?,
            normalized_subset_proof: compute_attenuation_witness(
                &delegable_family.scope,
                &delegable_family.scope,
            )?,
            aggregate_family_preservation: None,
        };
        let constrained_legacy = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: root_body(
                    "legacy-constrained-root",
                    issuer.public_key(),
                    subject.public_key(),
                ),
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: legacy_proof,
                budget_share_bps: Some(3_000),
            },
            &issuer,
        )?;
        let verified_family =
            verify_direct_aggregate_family_root(&delegable_family, &[issuer.public_key()])?;
        let family_proof = AttenuationProof {
            parent_scope_hash: scope_hash(&delegable_family.scope)?,
            child_scope_hash: scope_hash(&delegable_family.scope)?,
            normalized_subset_proof: compute_attenuation_witness(
                &delegable_family.scope,
                &delegable_family.scope,
            )?,
            aggregate_family_preservation: Some(verified_family.preservation_evidence()),
        };
        let constrained_family = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: delegable_family.body(),
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: family_proof,
                budget_share_bps: Some(3_000),
            },
            &issuer,
        )?;
        assert!(constrained_legacy.verify_signature()?);
        assert!(
            verify_direct_aggregate_family_root(&constrained_family, &[issuer.public_key()])
                .is_ok()
        );
        let trusted = [issuer.public_key(), subject.public_key()];

        for candidate in [
            &nondelegable,
            &capability_scoped,
            &nondelegable_family,
            &delegated,
            &constrained_legacy,
            &constrained_family,
        ] {
            assert!(matches!(
                store.record_aggregate_family_root(candidate, &trusted, 1_100),
                Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
            ));
        }
        assert_eq!(row_count(&path)?, 0);
        Ok(())
    }

    #[test]
    fn aggregate_family_root_rejects_token_above_transport_bound() -> TestResult {
        let directory = tempdir()?;
        let store = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let mut body = root_body("oversized-root", issuer.public_key(), subject.public_key());
        body.scope.grants[0].server_id =
            "x".repeat(super::MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES + 1);
        let token = CapabilityToken::sign(body, &issuer)?;

        assert!(matches!(
            store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100),
            Err(super::AggregateFamilyRootStoreError::InvalidRecord(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_missing_table_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TRIGGER chio_aggregate_family_roots_immutable_update;
             DROP TRIGGER chio_aggregate_family_roots_immutable_delete;
             DROP TABLE chio_aggregate_family_roots;",
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root("malformed-table"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_missing_immutability_trigger_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;

        assert!(matches!(
            store.resolve_aggregate_family_root("trigger-missing"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_noop_trigger_name_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        drop_update_guard(&connection)?;
        connection.execute_batch(
            "CREATE TRIGGER chio_aggregate_family_roots_immutable_update
             BEFORE UPDATE ON chio_aggregate_family_roots
             BEGIN SELECT 1; END;",
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root("trigger-squatted"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_unexpected_trigger_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TRIGGER chio_aggregate_family_roots_unexpected_insert
             AFTER INSERT ON chio_aggregate_family_roots
             BEGIN SELECT 1; END;",
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root("unexpected-trigger"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_dropped_table_does_not_recreate_on_restart() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch("DROP TABLE chio_aggregate_family_roots;")?;
            drop(store);
        }

        assert!(SqliteReceiptStore::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_dropped_tables_do_not_erase_migration_history() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch(
                "DROP TABLE chio_aggregate_family_roots;
                 DROP TABLE chio_aggregate_family_root_schema;",
            )?;
            drop(store);
        }

        assert!(SqliteReceiptStore::open(&path).is_err());
        assert!(SqliteReceiptStore::open_existing(&path).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_open_existing_runs_first_migration() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch(
                "DROP TABLE chio_aggregate_family_roots;
                 DROP TABLE chio_aggregate_family_root_schema;
                 DELETE FROM chio_module_schema_version
                 WHERE module = 'aggregate_family_root_authority';",
            )?;
            drop(store);
        }

        let reopened = SqliteReceiptStore::open_existing(&path)?;
        assert_eq!(
            reopened.resolve_aggregate_family_root("not-registered"),
            Err(AggregateFamilyRootResolutionError::Missing)
        );
        Ok(())
    }

    #[test]
    fn aggregate_family_root_ignores_database_wide_user_version() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            connection.execute_batch("PRAGMA user_version = 73;")?;
            drop(store);
        }

        let reopened = SqliteReceiptStore::open_existing(&path)?;
        assert_eq!(
            reopened.resolve_aggregate_family_root("not-registered"),
            Err(AggregateFamilyRootResolutionError::Missing)
        );
        Ok(())
    }

    #[test]
    fn aggregate_family_root_open_existing_rejects_tampered_schema() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        {
            let store = SqliteReceiptStore::open(&path)?;
            let connection = Connection::open(&path)?;
            drop_update_guard(&connection)?;
            drop(store);
        }

        assert!(SqliteReceiptStore::open_existing(&path).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_family_root_malformed_sqlite_schema_is_corrupt() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "PRAGMA writable_schema = ON;
             UPDATE sqlite_master
             SET sql = 'malformed'
             WHERE type = 'table' AND name = 'chio_aggregate_family_roots';
             PRAGMA writable_schema = OFF;
             PRAGMA schema_version = 424242;",
        )?;

        assert!(matches!(
            store.resolve_aggregate_family_root("corrupt-schema"),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn aggregate_family_root_busy_writer_is_unavailable() -> TestResult {
        let directory = tempdir()?;
        let path = directory.path().join("receipts.db");
        let store = SqliteReceiptStore::open(&path)?;
        store.writer_handle().run_write(|connection| {
            connection.execute_batch("PRAGMA busy_timeout = 0;")?;
            Ok(())
        })?;
        let lock = Connection::open(&path)?;
        lock.execute_batch("PRAGMA busy_timeout = 0; BEGIN IMMEDIATE;")?;
        let (issuer, _subject, token) = legacy_root("legacy-busy-store")?;

        assert!(matches!(
            store.record_aggregate_family_root(&token, &[issuer.public_key()], 1_100),
            Err(super::AggregateFamilyRootStoreError::Unavailable(_))
        ));
        lock.execute_batch("ROLLBACK;")?;
        Ok(())
    }

    #[test]
    fn aggregate_family_root_sqlite_error_classes_preserve_semantics() {
        for code in [
            rusqlite::ffi::SQLITE_BUSY,
            rusqlite::ffi::SQLITE_LOCKED,
            rusqlite::ffi::SQLITE_IOERR,
            rusqlite::ffi::SQLITE_CANTOPEN,
        ] {
            let resolver_error = super::sqlite_to_resolution_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ));
            assert!(matches!(
                resolver_error,
                AggregateFamilyRootResolutionError::Unavailable(_)
            ));
            let store_error = super::sqlite_to_store_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ));
            assert!(matches!(
                store_error,
                super::AggregateFamilyRootStoreError::Unavailable(_)
            ));
        }

        for code in [rusqlite::ffi::SQLITE_CORRUPT, rusqlite::ffi::SQLITE_NOTADB] {
            let resolver_error = super::sqlite_to_resolution_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ));
            assert!(matches!(
                resolver_error,
                AggregateFamilyRootResolutionError::Corrupt(_)
            ));
            let store_error = super::sqlite_to_store_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ));
            assert!(matches!(
                store_error,
                super::AggregateFamilyRootStoreError::Corrupt(_)
            ));
        }
    }
}
