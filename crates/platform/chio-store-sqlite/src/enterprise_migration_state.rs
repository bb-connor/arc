use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use chio_core::{canonical_json_bytes, sha256, Keypair, PublicKey, Signature};
use chio_security_types::ports::{Digest32, PortError, PortResult, RecordId};
use chio_security_types::{
    EnterpriseMigrationCasOutcome, EnterpriseMigrationControl, EnterpriseMigrationKey,
    EnterpriseMigrationMinimumHead, EnterpriseMigrationRegisterOutcome,
    EnterpriseMigrationScopeKind, EnterpriseMigrationStage, EnterpriseMigrationState,
    EnterpriseMigrationStateStore, EnterpriseMigrationTransition,
    EnterpriseMigrationTransitionBody, ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION,
    MAX_ENTERPRISE_MIGRATION_SIGNATURE_BYTES, MAX_ENTERPRISE_MIGRATION_SIGNER_BYTES,
};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use thiserror::Error;

const TABLE_NAME: &str = "enterprise_migration_transitions";
const NO_UPDATE_TRIGGER_NAME: &str = "enterprise_migration_transitions_no_update";
const NO_DELETE_TRIGGER_NAME: &str = "enterprise_migration_transitions_no_delete";
const CHAIN_TRIGGER_NAME: &str = "enterprise_migration_transitions_require_predecessor";

const CREATE_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS enterprise_migration_transitions (
    deployment_id TEXT NOT NULL CHECK (length(deployment_id) > 0 AND length(deployment_id) <= 256),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('deployment', 'provider', 'tool_server')),
    scope_id TEXT NOT NULL CHECK (length(scope_id) > 0 AND length(scope_id) <= 256),
    control TEXT NOT NULL CHECK (control IN ('key_log_verification', 'broker_credential_custody', 'broker_quota_enforcement', 'cage_enforcement', 'legacy_configuration')),
    signature_domain TEXT NOT NULL CHECK (signature_domain = 'chio.enterprise-migration-transition.v1'),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0 AND generation <= 3),
    from_stage INTEGER,
    to_stage INTEGER NOT NULL CHECK (to_stage >= 0 AND to_stage <= 3),
    prior_head_digest BLOB,
    posture_digest BLOB NOT NULL CHECK (length(posture_digest) = 32 AND posture_digest <> zeroblob(32)),
    evidence_digest BLOB NOT NULL CHECK (length(evidence_digest) = 32 AND evidence_digest <> zeroblob(32)),
    authorization_digest BLOB NOT NULL CHECK (length(authorization_digest) = 32 AND authorization_digest <> zeroblob(32)),
    intent_digest BLOB NOT NULL CHECK (length(intent_digest) = 32 AND intent_digest <> zeroblob(32)),
    trusted_at_unix_ms INTEGER NOT NULL CHECK (trusted_at_unix_ms > 0),
    signer_public_key TEXT NOT NULL CHECK (length(signer_public_key) > 0 AND length(signer_public_key) <= 8192),
    signature TEXT NOT NULL CHECK (length(signature) > 0 AND length(signature) <= 16384),
    transition_digest BLOB NOT NULL CHECK (length(transition_digest) = 32 AND transition_digest <> zeroblob(32)),
    PRIMARY KEY (deployment_id, scope_kind, scope_id, control, generation),
    UNIQUE (deployment_id, scope_kind, scope_id, control, transition_digest),
    CHECK (generation = to_stage),
    CHECK (
        (control = 'key_log_verification' AND scope_kind = 'deployment')
        OR (control IN ('broker_credential_custody', 'broker_quota_enforcement') AND scope_kind = 'provider')
        OR (control = 'cage_enforcement' AND scope_kind = 'tool_server')
        OR control = 'legacy_configuration'
    ),
    CHECK (
        (generation = 0 AND from_stage IS NULL AND prior_head_digest IS NULL AND to_stage = 0)
        OR
        (generation > 0 AND from_stage = generation - 1 AND length(prior_head_digest) = 32 AND prior_head_digest <> zeroblob(32))
    )
) STRICT
"#;

const CREATE_NO_UPDATE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS enterprise_migration_transitions_no_update
BEFORE UPDATE ON enterprise_migration_transitions
BEGIN
    SELECT RAISE(ABORT, 'enterprise migration transitions are append-only');
END
"#;

const CREATE_NO_DELETE_TRIGGER_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS enterprise_migration_transitions_no_delete
BEFORE DELETE ON enterprise_migration_transitions
BEGIN
    SELECT RAISE(ABORT, 'enterprise migration transitions cannot be deleted');
END
"#;

const CREATE_CHAIN_TRIGGER_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS enterprise_migration_transitions_require_predecessor
BEFORE INSERT ON enterprise_migration_transitions
WHEN NEW.generation > 0 AND NOT EXISTS (
    SELECT 1
    FROM enterprise_migration_transitions AS predecessor
    WHERE predecessor.deployment_id = NEW.deployment_id
      AND predecessor.scope_kind = NEW.scope_kind
      AND predecessor.scope_id = NEW.scope_id
      AND predecessor.control = NEW.control
      AND predecessor.generation = NEW.generation - 1
      AND predecessor.to_stage = NEW.from_stage
      AND predecessor.transition_digest = NEW.prior_head_digest
      AND predecessor.trusted_at_unix_ms <= NEW.trusted_at_unix_ms
)
BEGIN
    SELECT RAISE(ABORT, 'enterprise migration transition predecessor is absent or mismatched');
END
"#;

const SCHEMA_OBJECTS: [(&str, &str, &str); 4] = [
    ("table", TABLE_NAME, CREATE_TABLE_SQL),
    (
        "trigger",
        NO_UPDATE_TRIGGER_NAME,
        CREATE_NO_UPDATE_TRIGGER_SQL,
    ),
    (
        "trigger",
        NO_DELETE_TRIGGER_NAME,
        CREATE_NO_DELETE_TRIGGER_SQL,
    ),
    ("trigger", CHAIN_TRIGGER_NAME, CREATE_CHAIN_TRIGGER_SQL),
];

#[derive(Debug, Error)]
pub enum SqliteEnterpriseMigrationStateStoreError {
    #[error("enterprise migration state requires an absolute durable filesystem path")]
    VolatilePath,
    #[error("enterprise migration state path contains a symlink or dot component")]
    UnsafePath,
    #[error("enterprise migration state database must have exactly one hard link")]
    HardLinkedPath,
    #[error("enterprise migration state database file identity changed")]
    FileIdentityChanged,
    #[error("enterprise migration state requires at least one trusted transition signer")]
    MissingTrustedSigner,
    #[error("enterprise migration state open policy is invalid")]
    InvalidOpenPolicy,
    #[error("enterprise migration state schema or transition ledger failed integrity validation")]
    Integrity,
    #[error("enterprise migration transition cryptography failed")]
    Cryptography,
    #[error("enterprise migration state I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("enterprise migration state database failed: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Trust and anti-rollback inputs kept outside the database being opened.
#[derive(Clone)]
pub struct SqliteEnterpriseMigrationOpenPolicy {
    trusted_signers: BTreeMap<String, PublicKey>,
    minimum_heads: BTreeMap<EnterpriseMigrationKey, EnterpriseMigrationMinimumHead>,
}

impl SqliteEnterpriseMigrationOpenPolicy {
    pub fn new(
        trusted_signers: Vec<PublicKey>,
        minimum_heads: Vec<EnterpriseMigrationMinimumHead>,
    ) -> Result<Self, SqliteEnterpriseMigrationStateStoreError> {
        let mut trusted = BTreeMap::new();
        for signer in trusted_signers {
            trusted.insert(signer.to_hex(), signer);
        }
        if trusted.is_empty() {
            return Err(SqliteEnterpriseMigrationStateStoreError::MissingTrustedSigner);
        }
        let mut anchors = BTreeMap::new();
        for minimum_head in minimum_heads {
            if !minimum_head.is_valid() || anchors.contains_key(&minimum_head.key) {
                return Err(SqliteEnterpriseMigrationStateStoreError::InvalidOpenPolicy);
            }
            anchors.insert(minimum_head.key.clone(), minimum_head);
        }
        Ok(Self {
            trusted_signers: trusted,
            minimum_heads: anchors,
        })
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct DatabaseFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Clone)]
struct DatabaseFileIdentity {
    canonical_path: PathBuf,
}

pub struct SqliteEnterpriseMigrationStateStore {
    connection: Mutex<Connection>,
    path: PathBuf,
    identity_file: File,
    identity: DatabaseFileIdentity,
    trusted_signers: BTreeMap<String, PublicKey>,
    minimum_heads: BTreeMap<EnterpriseMigrationKey, EnterpriseMigrationMinimumHead>,
}

impl SqliteEnterpriseMigrationStateStore {
    pub fn open(
        path: impl AsRef<Path>,
        policy: SqliteEnterpriseMigrationOpenPolicy,
    ) -> Result<Self, SqliteEnterpriseMigrationStateStoreError> {
        let path = validate_durable_path(path.as_ref())?;
        reject_symlink_components(&path)?;
        let database_exists = path.try_exists()?;
        if !database_exists && !policy.minimum_heads.is_empty() {
            return Err(SqliteEnterpriseMigrationStateStoreError::Integrity);
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(SqliteEnterpriseMigrationStateStoreError::UnsafePath)?;
        reject_symlink_components(parent)?;
        fs::create_dir_all(parent)?;
        reject_symlink_components(&path)?;
        if path.try_exists()? {
            validate_single_link_regular_file(&path)?;
        }
        validate_database_sidecars(&path)?;

        let mut open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if policy.minimum_heads.is_empty() {
            open_flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags(&path, open_flags)?;
        connection.execute_batch(
            "PRAGMA synchronous = FULL;\
             PRAGMA busy_timeout = 5000;\
             PRAGMA trusted_schema = OFF;",
        )?;
        initialize_schema(&connection)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;\
             PRAGMA synchronous = FULL;",
        )?;
        verify_storage_pragmas(&connection)?;

        reject_symlink_components(&path)?;
        validate_single_link_regular_file(&path)?;
        let identity_file = open_database_identity_file(&path)?;
        let identity = database_file_identity(&path, &identity_file)?;
        let store = Self {
            connection: Mutex::new(connection),
            path,
            identity_file,
            identity,
            trusted_signers: policy.trusted_signers,
            minimum_heads: policy.minimum_heads,
        };
        store.verify_file_identity()?;
        {
            let connection = store
                .connection
                .lock()
                .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Integrity)?;
            verify_schema(&connection)?;
            verify_all_chains(&connection, &store.trusted_signers, &store.minimum_heads)
                .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Integrity)?;
        }
        store.verify_file_identity()?;
        Ok(store)
    }

    fn connection(&self) -> PortResult<MutexGuard<'_, Connection>> {
        self.verify_file_identity()
            .map_err(|_| PortError::integrity_failure())?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| PortError::unavailable())?;
        verify_schema(&connection).map_err(|_| PortError::integrity_failure())?;
        verify_storage_pragmas(&connection).map_err(|_| PortError::integrity_failure())?;
        Ok(connection)
    }

    fn verify_file_identity(&self) -> Result<(), SqliteEnterpriseMigrationStateStoreError> {
        validate_database_binding(&self.path, &self.identity_file, &self.identity)?;
        validate_database_sidecars(&self.path)
    }

    #[must_use]
    pub fn minimum_head(
        &self,
        key: &EnterpriseMigrationKey,
    ) -> Option<&EnterpriseMigrationMinimumHead> {
        self.minimum_heads.get(key)
    }
}

/// Sign a typed transition body with its declared signer.
pub fn sign_enterprise_migration_transition(
    body: EnterpriseMigrationTransitionBody,
    signer: &Keypair,
) -> Result<EnterpriseMigrationTransition, SqliteEnterpriseMigrationStateStoreError> {
    body.validate_shape()
        .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Cryptography)?;
    if body.signer_public_key != signer.public_key().to_hex() {
        return Err(SqliteEnterpriseMigrationStateStoreError::Cryptography);
    }
    let (signature, _) = signer
        .sign_canonical(&body)
        .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Cryptography)?;
    let transition = EnterpriseMigrationTransition {
        body,
        signature: signature.to_hex(),
    };
    transition
        .validate_shape()
        .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Cryptography)?;
    Ok(transition)
}

pub fn enterprise_migration_transition_digest(
    transition: &EnterpriseMigrationTransition,
) -> Result<Digest32, SqliteEnterpriseMigrationStateStoreError> {
    transition
        .validate_shape()
        .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Cryptography)?;
    let public_key = PublicKey::from_hex(&transition.body.signer_public_key)
        .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Cryptography)?;
    let signature = Signature::from_hex(&transition.signature)
        .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Cryptography)?;
    if public_key.to_hex() != transition.body.signer_public_key
        || signature.to_hex() != transition.signature
    {
        return Err(SqliteEnterpriseMigrationStateStoreError::Cryptography);
    }
    let canonical_body = canonical_json_bytes(&transition.body)
        .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Cryptography)?;
    if !public_key.verify(&canonical_body, &signature) {
        return Err(SqliteEnterpriseMigrationStateStoreError::Cryptography);
    }
    let canonical = canonical_json_bytes(transition)
        .map_err(|_| SqliteEnterpriseMigrationStateStoreError::Cryptography)?;
    Ok(Digest32::new(*sha256(&canonical).as_bytes()))
}

impl EnterpriseMigrationStateStore for SqliteEnterpriseMigrationStateStore {
    fn register(
        &self,
        transition: &EnterpriseMigrationTransition,
    ) -> PortResult<EnterpriseMigrationRegisterOutcome> {
        let validated = validate_transition(transition, &self.trusted_signers)?;
        if transition.body.generation != 0 {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PortError::unavailable())?;
        verify_schema(&transaction).map_err(|_| PortError::integrity_failure())?;
        let existing = load_verified_state(
            &transaction,
            &transition.body.key,
            &self.trusted_signers,
            self.minimum_heads.get(&transition.body.key),
        )?;
        if let Some(existing) = existing {
            transaction.commit().map_err(|_| PortError::unavailable())?;
            self.verify_file_identity()
                .map_err(|_| PortError::integrity_failure())?;
            if existing.generation == 0 && existing.transition_digest == validated.digest {
                return Ok(EnterpriseMigrationRegisterOutcome::Existing(existing));
            }
            return Ok(EnterpriseMigrationRegisterOutcome::Conflict(existing));
        }
        insert_transition(&transaction, transition, validated.digest)?;
        let registered = load_verified_state(
            &transaction,
            &transition.body.key,
            &self.trusted_signers,
            self.minimum_heads.get(&transition.body.key),
        )?
        .ok_or_else(PortError::integrity_failure)?;
        transaction.commit().map_err(|_| PortError::unavailable())?;
        self.verify_file_identity()
            .map_err(|_| PortError::integrity_failure())?;
        Ok(EnterpriseMigrationRegisterOutcome::Registered(registered))
    }

    fn load(&self, key: &EnterpriseMigrationKey) -> PortResult<Option<EnterpriseMigrationState>> {
        if !key.control_scope_is_valid() {
            return Err(PortError::invalid_data());
        }
        let connection = self.connection()?;
        let state = load_verified_state(
            &connection,
            key,
            &self.trusted_signers,
            self.minimum_heads.get(key),
        )?;
        drop(connection);
        self.verify_file_identity()
            .map_err(|_| PortError::integrity_failure())?;
        Ok(state)
    }

    fn compare_and_promote(
        &self,
        transition: &EnterpriseMigrationTransition,
    ) -> PortResult<EnterpriseMigrationCasOutcome> {
        let validated = validate_transition(transition, &self.trusted_signers)?;
        if transition.body.generation == 0 {
            return Err(PortError::invalid_data());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PortError::unavailable())?;
        verify_schema(&transaction).map_err(|_| PortError::integrity_failure())?;
        let current = load_verified_state(
            &transaction,
            &transition.body.key,
            &self.trusted_signers,
            self.minimum_heads.get(&transition.body.key),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if !transition_extends_state(transition, &current) {
            transaction.commit().map_err(|_| PortError::unavailable())?;
            self.verify_file_identity()
                .map_err(|_| PortError::integrity_failure())?;
            return Ok(EnterpriseMigrationCasOutcome::Conflict(current));
        }
        insert_transition(&transaction, transition, validated.digest)?;
        let promoted = load_verified_state(
            &transaction,
            &transition.body.key,
            &self.trusted_signers,
            self.minimum_heads.get(&transition.body.key),
        )?
        .ok_or_else(PortError::integrity_failure)?;
        transaction.commit().map_err(|_| PortError::unavailable())?;
        self.verify_file_identity()
            .map_err(|_| PortError::integrity_failure())?;
        Ok(EnterpriseMigrationCasOutcome::Promoted(promoted))
    }
}

struct ValidatedTransition {
    digest: Digest32,
}

fn validate_transition(
    transition: &EnterpriseMigrationTransition,
    trusted_signers: &BTreeMap<String, PublicKey>,
) -> PortResult<ValidatedTransition> {
    if !trusted_signers.contains_key(&transition.body.signer_public_key) {
        return Err(PortError::invalid_data());
    }
    let digest = enterprise_migration_transition_digest(transition)
        .map_err(|_| PortError::invalid_data())?;
    Ok(ValidatedTransition { digest })
}

fn transition_extends_state(
    transition: &EnterpriseMigrationTransition,
    current: &EnterpriseMigrationState,
) -> bool {
    transition.body.key == current.key
        && transition.body.from_stage == Some(current.stage)
        && transition.body.to_stage == current.stage.next().unwrap_or(current.stage)
        && transition.body.generation == current.generation.saturating_add(1)
        && transition.body.prior_head_digest == Some(current.transition_digest)
        && transition.body.trusted_at_unix_ms >= current.updated_at_unix_ms
}

fn insert_transition(
    transaction: &Transaction<'_>,
    transition: &EnterpriseMigrationTransition,
    digest: Digest32,
) -> PortResult<()> {
    let body = &transition.body;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO enterprise_migration_transitions (
                deployment_id,
                scope_kind,
                scope_id,
                control,
                signature_domain,
                schema_version,
                generation,
                from_stage,
                to_stage,
                prior_head_digest,
                posture_digest,
                evidence_digest,
                authorization_digest,
                intent_digest,
                trusted_at_unix_ms,
                signer_public_key,
                signature,
                transition_digest
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
            )
            "#,
            params![
                body.key.deployment_id.as_str(),
                scope_kind_name(body.key.scope_kind),
                body.key.scope_id.as_str(),
                control_name(body.key.control),
                body.signature_domain,
                i64::from(body.schema_version),
                encode_u64(body.generation)?,
                body.from_stage.map(stage_number),
                stage_number(body.to_stage),
                body.prior_head_digest
                    .map(|value| value.as_bytes().to_vec()),
                body.posture_digest.as_bytes().as_slice(),
                body.evidence_digest.as_bytes().as_slice(),
                body.authorization_digest.as_bytes().as_slice(),
                body.intent_digest.as_bytes().as_slice(),
                encode_u64(body.trusted_at_unix_ms)?,
                body.signer_public_key,
                transition.signature,
                digest.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| PortError::integrity_failure())?;
    if inserted != 1 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn load_verified_state(
    connection: &Connection,
    key: &EnterpriseMigrationKey,
    trusted_signers: &BTreeMap<String, PublicKey>,
    minimum_head: Option<&EnterpriseMigrationMinimumHead>,
) -> PortResult<Option<EnterpriseMigrationState>> {
    let rows = load_transition_rows(connection, key)?;
    if rows.is_empty() {
        if minimum_head.is_some() {
            return Err(PortError::integrity_failure());
        }
        return Ok(None);
    }

    let mut prior: Option<EnterpriseMigrationState> = None;
    let mut anchored = minimum_head.is_none();
    for row in rows {
        let stored_digest = row.transition_digest;
        let transition = row.transition(key.clone())?;
        let validated = validate_transition(&transition, trusted_signers)
            .map_err(|_| PortError::integrity_failure())?;
        if validated.digest != stored_digest {
            return Err(PortError::integrity_failure());
        }
        match &prior {
            None if transition.body.generation == 0 => {}
            Some(previous) if transition_extends_state(&transition, previous) => {}
            _ => return Err(PortError::integrity_failure()),
        }
        let state = state_from_transition(&transition, validated.digest);
        if let Some(minimum) = minimum_head {
            if state.generation == minimum.minimum_generation {
                if state.transition_digest != minimum.transition_digest {
                    return Err(PortError::integrity_failure());
                }
                anchored = true;
            }
        }
        prior = Some(state);
    }
    if !anchored {
        return Err(PortError::integrity_failure());
    }
    Ok(prior)
}

fn state_from_transition(
    transition: &EnterpriseMigrationTransition,
    transition_digest: Digest32,
) -> EnterpriseMigrationState {
    EnterpriseMigrationState {
        schema_version: transition.body.schema_version,
        key: transition.body.key.clone(),
        stage: transition.body.to_stage,
        generation: transition.body.generation,
        transition_digest,
        prior_head_digest: transition.body.prior_head_digest,
        posture_digest: transition.body.posture_digest,
        evidence_digest: transition.body.evidence_digest,
        authorization_digest: transition.body.authorization_digest,
        intent_digest: transition.body.intent_digest,
        updated_at_unix_ms: transition.body.trusted_at_unix_ms,
        signer_public_key: transition.body.signer_public_key.clone(),
    }
}

struct StoredTransitionRow {
    signature_domain: String,
    schema_version: i64,
    generation: i64,
    from_stage: Option<i64>,
    to_stage: i64,
    prior_head_digest: Option<Vec<u8>>,
    posture_digest: Vec<u8>,
    evidence_digest: Vec<u8>,
    authorization_digest: Vec<u8>,
    intent_digest: Vec<u8>,
    trusted_at_unix_ms: i64,
    signer_public_key: String,
    signature: String,
    transition_digest: Digest32,
}

impl StoredTransitionRow {
    fn transition(self, key: EnterpriseMigrationKey) -> PortResult<EnterpriseMigrationTransition> {
        Ok(EnterpriseMigrationTransition {
            body: EnterpriseMigrationTransitionBody {
                signature_domain: self.signature_domain,
                schema_version: u8::try_from(self.schema_version)
                    .map_err(|_| PortError::integrity_failure())?,
                key,
                generation: decode_u64(self.generation)?,
                from_stage: self.from_stage.map(decode_stage).transpose()?,
                to_stage: decode_stage(self.to_stage)?,
                prior_head_digest: self.prior_head_digest.map(decode_digest).transpose()?,
                posture_digest: decode_digest(self.posture_digest)?,
                evidence_digest: decode_digest(self.evidence_digest)?,
                authorization_digest: decode_digest(self.authorization_digest)?,
                intent_digest: decode_digest(self.intent_digest)?,
                trusted_at_unix_ms: decode_u64(self.trusted_at_unix_ms)?,
                signer_public_key: self.signer_public_key,
            },
            signature: self.signature,
        })
    }
}

fn load_transition_rows(
    connection: &Connection,
    key: &EnterpriseMigrationKey,
) -> PortResult<Vec<StoredTransitionRow>> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT signature_domain,
                   schema_version,
                   generation,
                   from_stage,
                   to_stage,
                   prior_head_digest,
                   posture_digest,
                   evidence_digest,
                   authorization_digest,
                   intent_digest,
                   trusted_at_unix_ms,
                   signer_public_key,
                   signature,
                   transition_digest
            FROM enterprise_migration_transitions
            WHERE deployment_id = ?1
              AND scope_kind = ?2
              AND scope_id = ?3
              AND control = ?4
            ORDER BY generation ASC
            "#,
        )
        .map_err(|_| PortError::integrity_failure())?;
    let mapped = statement
        .query_map(
            params![
                key.deployment_id.as_str(),
                scope_kind_name(key.scope_kind),
                key.scope_id.as_str(),
                control_name(key.control),
            ],
            |row| {
                let transition_digest: Vec<u8> = row.get(13)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    transition_digest,
                ))
            },
        )
        .map_err(|_| PortError::integrity_failure())?;
    let mut rows = Vec::new();
    for row in mapped {
        let (
            signature_domain,
            schema_version,
            generation,
            from_stage,
            to_stage,
            prior_head_digest,
            posture_digest,
            evidence_digest,
            authorization_digest,
            intent_digest,
            trusted_at_unix_ms,
            signer_public_key,
            signature,
            transition_digest,
        ) = row.map_err(|_| PortError::integrity_failure())?;
        rows.push(StoredTransitionRow {
            signature_domain,
            schema_version,
            generation,
            from_stage,
            to_stage,
            prior_head_digest,
            posture_digest,
            evidence_digest,
            authorization_digest,
            intent_digest,
            trusted_at_unix_ms,
            signer_public_key,
            signature,
            transition_digest: decode_digest(transition_digest)?,
        });
    }
    Ok(rows)
}

fn verify_all_chains(
    connection: &Connection,
    trusted_signers: &BTreeMap<String, PublicKey>,
    minimum_heads: &BTreeMap<EnterpriseMigrationKey, EnterpriseMigrationMinimumHead>,
) -> PortResult<()> {
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT deployment_id, scope_kind, scope_id, control \
             FROM enterprise_migration_transitions",
        )
        .map_err(|_| PortError::integrity_failure())?;
    let mapped = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| PortError::integrity_failure())?;
    let mut keys = BTreeSet::new();
    for row in mapped {
        let (deployment_id, scope_kind, scope_id, control) =
            row.map_err(|_| PortError::integrity_failure())?;
        let key = EnterpriseMigrationKey {
            deployment_id: RecordId::new(deployment_id)
                .map_err(|_| PortError::integrity_failure())?,
            scope_kind: decode_scope_kind(&scope_kind)?,
            scope_id: RecordId::new(scope_id).map_err(|_| PortError::integrity_failure())?,
            control: decode_control(&control)?,
        };
        if !key.control_scope_is_valid() {
            return Err(PortError::integrity_failure());
        }
        keys.insert(key);
    }
    drop(statement);
    for key in minimum_heads.keys() {
        keys.insert(key.clone());
    }
    for key in keys {
        load_verified_state(connection, &key, trusted_signers, minimum_heads.get(&key))?;
    }
    Ok(())
}

fn initialize_schema(
    connection: &Connection,
) -> Result<(), SqliteEnterpriseMigrationStateStoreError> {
    let legacy_table_exists =
        sqlite_object_exists(connection, "table", "enterprise_migration_state")?;
    if legacy_table_exists {
        return Err(SqliteEnterpriseMigrationStateStoreError::Integrity);
    }
    if sqlite_object_exists(connection, "table", TABLE_NAME)? {
        return verify_schema(connection);
    }
    let bootstrap = format!(
        "BEGIN IMMEDIATE; {CREATE_TABLE_SQL}; {CREATE_NO_UPDATE_TRIGGER_SQL}; \
         {CREATE_NO_DELETE_TRIGGER_SQL}; {CREATE_CHAIN_TRIGGER_SQL}; COMMIT;"
    );
    if let Err(error) = connection.execute_batch(&bootstrap) {
        let _ = connection.execute_batch("ROLLBACK;");
        return Err(error.into());
    }
    verify_schema(connection)
}

fn verify_schema(connection: &Connection) -> Result<(), SqliteEnterpriseMigrationStateStoreError> {
    if ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION != 1
        || MAX_ENTERPRISE_MIGRATION_SIGNER_BYTES != 8_192
        || MAX_ENTERPRISE_MIGRATION_SIGNATURE_BYTES != 16_384
    {
        return Err(SqliteEnterpriseMigrationStateStoreError::Integrity);
    }
    let legacy_table_exists =
        sqlite_object_exists(connection, "table", "enterprise_migration_state")?;
    if legacy_table_exists {
        return Err(SqliteEnterpriseMigrationStateStoreError::Integrity);
    }
    for (object_type, object_name, expected_sql) in SCHEMA_OBJECTS {
        let actual_sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
                params![object_type, object_name],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(SqliteEnterpriseMigrationStateStoreError::Integrity)?;
        if normalize_sql(&actual_sql) != normalize_sql(expected_sql) {
            return Err(SqliteEnterpriseMigrationStateStoreError::Integrity);
        }
    }
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_master \
         WHERE type = 'trigger' AND tbl_name = ?1 ORDER BY name ASC",
    )?;
    let actual = statement
        .query_map(params![TABLE_NAME], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected = vec![
        String::from(CHAIN_TRIGGER_NAME),
        String::from(NO_DELETE_TRIGGER_NAME),
        String::from(NO_UPDATE_TRIGGER_NAME),
    ];
    expected.sort_unstable();
    if actual != expected {
        return Err(SqliteEnterpriseMigrationStateStoreError::Integrity);
    }
    Ok(())
}

fn verify_storage_pragmas(
    connection: &Connection,
) -> Result<(), SqliteEnterpriseMigrationStateStoreError> {
    let journal_mode =
        connection.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;
    let synchronous = connection.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))?;
    let trusted_schema =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get::<_, i64>(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 || trusted_schema != 0 {
        return Err(SqliteEnterpriseMigrationStateStoreError::Integrity);
    }
    Ok(())
}

fn sqlite_object_exists(
    connection: &Connection,
    object_type: &str,
    object_name: &str,
) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2)",
        params![object_type, object_name],
        |row| row.get(0),
    )
}

fn normalize_sql(sql: &str) -> String {
    let normalized = sql
        .trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    normalized.replace(" IF NOT EXISTS ", " ")
}

fn validate_durable_path(path: &Path) -> Result<PathBuf, SqliteEnterpriseMigrationStateStoreError> {
    let text = path.to_string_lossy();
    if path.as_os_str().is_empty()
        || !path.is_absolute()
        || text == ":memory:"
        || text.to_ascii_lowercase().starts_with("file:")
    {
        return Err(SqliteEnterpriseMigrationStateStoreError::VolatilePath);
    }
    for component in path.components() {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(SqliteEnterpriseMigrationStateStoreError::UnsafePath);
        }
    }
    Ok(path.to_path_buf())
}

fn reject_symlink_components(path: &Path) -> Result<(), SqliteEnterpriseMigrationStateStoreError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(SqliteEnterpriseMigrationStateStoreError::UnsafePath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_single_link_regular_file(
    path: &Path,
) -> Result<(), SqliteEnterpriseMigrationStateStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(SqliteEnterpriseMigrationStateStoreError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(SqliteEnterpriseMigrationStateStoreError::HardLinkedPath);
        }
    }
    Ok(())
}

fn validate_database_sidecars(
    database_path: &Path,
) -> Result<(), SqliteEnterpriseMigrationStateStoreError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                reject_symlink_components(&sidecar)?;
                validate_single_link_regular_file(&sidecar)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn database_file_identity(
    path: &Path,
    file: &File,
) -> Result<DatabaseFileIdentity, SqliteEnterpriseMigrationStateStoreError> {
    let path_metadata = fs::symlink_metadata(path)?;
    let file_metadata = file.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !file_metadata.file_type().is_file()
    {
        return Err(SqliteEnterpriseMigrationStateStoreError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.nlink() != 1
            || file_metadata.nlink() != 1
            || path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
        {
            return Err(SqliteEnterpriseMigrationStateStoreError::HardLinkedPath);
        }
        Ok(DatabaseFileIdentity {
            device: file_metadata.dev(),
            inode: file_metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(DatabaseFileIdentity {
            canonical_path: fs::canonicalize(path)?,
        })
    }
}

#[cfg(unix)]
fn open_database_identity_file(
    path: &Path,
) -> Result<File, SqliteEnterpriseMigrationStateStoreError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| SqliteEnterpriseMigrationStateStoreError::Io(error.into()))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_database_identity_file(
    path: &Path,
) -> Result<File, SqliteEnterpriseMigrationStateStoreError> {
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?)
}

fn validate_database_binding(
    path: &Path,
    file: &File,
    expected: &DatabaseFileIdentity,
) -> Result<(), SqliteEnterpriseMigrationStateStoreError> {
    reject_symlink_components(path)?;
    let current = database_file_identity(path, file)?;
    #[cfg(unix)]
    if current.device != expected.device || current.inode != expected.inode {
        return Err(SqliteEnterpriseMigrationStateStoreError::FileIdentityChanged);
    }
    #[cfg(not(unix))]
    if current.canonical_path != expected.canonical_path {
        return Err(SqliteEnterpriseMigrationStateStoreError::FileIdentityChanged);
    }
    Ok(())
}

fn encode_u64(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

fn decode_u64(value: i64) -> PortResult<u64> {
    u64::try_from(value).map_err(|_| PortError::integrity_failure())
}

fn decode_digest(value: Vec<u8>) -> PortResult<Digest32> {
    <[u8; 32]>::try_from(value)
        .map(Digest32::new)
        .map_err(|_| PortError::integrity_failure())
}

const fn stage_number(stage: EnterpriseMigrationStage) -> i64 {
    match stage {
        EnterpriseMigrationStage::Disabled => 0,
        EnterpriseMigrationStage::Shadow => 1,
        EnterpriseMigrationStage::Enforced => 2,
        EnterpriseMigrationStage::LegacyRemoved => 3,
    }
}

fn decode_stage(stage: i64) -> PortResult<EnterpriseMigrationStage> {
    match stage {
        0 => Ok(EnterpriseMigrationStage::Disabled),
        1 => Ok(EnterpriseMigrationStage::Shadow),
        2 => Ok(EnterpriseMigrationStage::Enforced),
        3 => Ok(EnterpriseMigrationStage::LegacyRemoved),
        _ => Err(PortError::integrity_failure()),
    }
}

const fn scope_kind_name(scope_kind: EnterpriseMigrationScopeKind) -> &'static str {
    match scope_kind {
        EnterpriseMigrationScopeKind::Deployment => "deployment",
        EnterpriseMigrationScopeKind::Provider => "provider",
        EnterpriseMigrationScopeKind::ToolServer => "tool_server",
    }
}

fn decode_scope_kind(value: &str) -> PortResult<EnterpriseMigrationScopeKind> {
    match value {
        "deployment" => Ok(EnterpriseMigrationScopeKind::Deployment),
        "provider" => Ok(EnterpriseMigrationScopeKind::Provider),
        "tool_server" => Ok(EnterpriseMigrationScopeKind::ToolServer),
        _ => Err(PortError::integrity_failure()),
    }
}

const fn control_name(control: EnterpriseMigrationControl) -> &'static str {
    match control {
        EnterpriseMigrationControl::KeyLogVerification => "key_log_verification",
        EnterpriseMigrationControl::BrokerCredentialCustody => "broker_credential_custody",
        EnterpriseMigrationControl::BrokerQuotaEnforcement => "broker_quota_enforcement",
        EnterpriseMigrationControl::CageEnforcement => "cage_enforcement",
        EnterpriseMigrationControl::LegacyConfiguration => "legacy_configuration",
    }
}

fn decode_control(value: &str) -> PortResult<EnterpriseMigrationControl> {
    match value {
        "key_log_verification" => Ok(EnterpriseMigrationControl::KeyLogVerification),
        "broker_credential_custody" => Ok(EnterpriseMigrationControl::BrokerCredentialCustody),
        "broker_quota_enforcement" => Ok(EnterpriseMigrationControl::BrokerQuotaEnforcement),
        "cage_enforcement" => Ok(EnterpriseMigrationControl::CageEnforcement),
        "legacy_configuration" => Ok(EnterpriseMigrationControl::LegacyConfiguration),
        _ => Err(PortError::integrity_failure()),
    }
}
