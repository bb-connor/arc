use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use chio_core::canonical::canonical_json_bytes;
use chio_core::hashing::sha256;
use chio_security_types::ports::{
    BoundedVec, Digest32, PortError, PortResult, RecordId, SealedDecoyRegistryStore, TenantId,
    WatermarkObservationStore, WatermarkSequenceStore,
};
use chio_security_types::{
    DecoyAeadNonce, DecoyArtifactLookup, DecoyScan, DecoySurface, EncryptedDecoyEnvelope,
    SealedDecoyCasRequest, SealedDecoyPage, SealedDecoyRecord, SealedMarkerLookup,
    SealedPublicRefLookup, WatermarkObservation, WatermarkObservationResult, WatermarkSequenceKey,
    WatermarkSequenceReservation, WatermarkSequenceReservationResult,
    MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row, Rows, TransactionBehavior};

const RECORDS_TABLE: &str = "sealed_decoy_records_v1";
const OPERATIONS_TABLE: &str = "sealed_decoy_operation_owners_v1";
const TRANSITIONS_TABLE: &str = "sealed_decoy_transitions_v1";
const SEQUENCE_HEADS_TABLE: &str = "watermark_sequence_heads_v1";
const SEQUENCE_OPERATIONS_TABLE: &str = "watermark_sequence_operations_v1";
const OBSERVATIONS_TABLE: &str = "watermark_observations_v1";
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct SqliteSealedDecoyRegistryStore {
    connection: Mutex<Connection>,
}

impl SqliteSealedDecoyRegistryStore {
    pub fn open(path: impl AsRef<Path>) -> PortResult<Self> {
        let path = path.as_ref();
        validate_durable_path(path)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|_| PortError::unavailable())?;
            }
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(path, flags).map_err(sqlite_error)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(sqlite_error)?;
        migrate(&connection)?;
        verify_runtime_configuration(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> PortResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| PortError::unavailable())
    }
}

impl SealedDecoyRegistryStore for SqliteSealedDecoyRegistryStore {
    fn load_by_id(&self, id: &DecoyArtifactLookup) -> PortResult<Option<SealedDecoyRecord>> {
        let connection = self.connection()?;
        load_record_by_id(&connection, &id.tenant_id, &id.artifact_token)
    }

    fn load_by_marker(&self, lookup: &SealedMarkerLookup) -> PortResult<Option<SealedDecoyRecord>> {
        let connection = self.connection()?;
        load_record_by_marker(
            &connection,
            &lookup.tenant_id,
            lookup.surface,
            &lookup.marker_token,
        )
    }

    fn load_by_public_ref(
        &self,
        lookup: &SealedPublicRefLookup,
    ) -> PortResult<Option<SealedDecoyRecord>> {
        let connection = self.connection()?;
        load_record_by_public_ref(&connection, &lookup.tenant_id, &lookup.public_ref_token)
    }

    fn compare_and_swap(&self, request: &SealedDecoyCasRequest) -> PortResult<SealedDecoyRecord> {
        validate_request(request)?;
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;

        if let Some(stored) = load_transition(
            &transaction,
            &request.record.tenant_id,
            &request.transition_token,
        )? {
            validate_transition_references(&transaction, &stored)?;
            if stored.request_hash != request_hash {
                return Err(PortError::conflict());
            }
            if stored.operation_token != request.operation_token || stored.result != request.record
            {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored.result);
        }

        let operation_owner = load_operation_owner(
            &transaction,
            &request.record.tenant_id,
            &request.operation_token,
        )?;
        if let Some(artifact) = operation_owner {
            load_record_by_id(&transaction, &request.record.tenant_id, &artifact)?
                .ok_or_else(PortError::integrity_failure)?;
            if artifact != request.record.artifact_token {
                return Err(PortError::conflict());
            }
        }

        let current = load_record_by_id(
            &transaction,
            &request.record.tenant_id,
            &request.record.artifact_token,
        )?;
        validate_cas_state(current.as_ref(), request)?;
        validate_unique_indexes(&transaction, &request.record)?;

        match current {
            None => insert_record(&transaction, &request.record)?,
            Some(_) => update_record(&transaction, request)?,
        }

        if operation_owner.is_none() {
            insert_operation_owner(
                &transaction,
                &request.record.tenant_id,
                &request.operation_token,
                &request.record.artifact_token,
            )?;
        }
        insert_transition(&transaction, request, &request_hash)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(request.record.clone())
    }

    fn scan(&self, scan: &DecoyScan) -> PortResult<SealedDecoyPage> {
        scan.validate().map_err(|_| PortError::invalid_data())?;
        let connection = self.connection()?;
        let fetch_limit = i64::from(scan.limit) + 1;
        let raw_records = if let Some(cursor) = scan.after_artifact_token {
            let mut statement = connection
                .prepare(
                    r#"
                    SELECT tenant_id, artifact_token, public_ref_token, surface, marker_token,
                           version_hash, generation, nonce, ciphertext
                    FROM sealed_decoy_records_v1
                    WHERE tenant_id = ?1 AND artifact_token > ?2
                    ORDER BY artifact_token ASC
                    LIMIT ?3
                    "#,
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query(params![
                    scan.tenant_id.as_str(),
                    &cursor.as_bytes()[..],
                    fetch_limit
                ])
                .map_err(sqlite_error)?;
            collect_raw_records(rows)?
        } else {
            let mut statement = connection
                .prepare(
                    r#"
                    SELECT tenant_id, artifact_token, public_ref_token, surface, marker_token,
                           version_hash, generation, nonce, ciphertext
                    FROM sealed_decoy_records_v1
                    WHERE tenant_id = ?1
                    ORDER BY artifact_token ASC
                    LIMIT ?2
                    "#,
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query(params![scan.tenant_id.as_str(), fetch_limit])
                .map_err(sqlite_error)?;
            collect_raw_records(rows)?
        };

        let mut records = raw_records
            .into_iter()
            .map(decode_record)
            .collect::<PortResult<Vec<_>>>()?;
        if records
            .iter()
            .any(|record| record.tenant_id != scan.tenant_id)
        {
            return Err(PortError::integrity_failure());
        }
        let page_limit = usize::from(scan.limit);
        let has_more = records.len() > page_limit;
        records.truncate(page_limit);
        let next_artifact_token = if has_more {
            records.last().map(|record| record.artifact_token)
        } else {
            None
        };
        Ok(SealedDecoyPage {
            records: BoundedVec::new(records).map_err(|_| PortError::integrity_failure())?,
            next_artifact_token,
        })
    }
}

impl WatermarkSequenceStore for SqliteSealedDecoyRegistryStore {
    fn reserve(
        &self,
        request: &WatermarkSequenceReservation,
    ) -> PortResult<WatermarkSequenceReservationResult> {
        if request.sequence == 0 {
            return Err(PortError::invalid_data());
        }
        to_i64(request.sequence)?;
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;

        if let Some(stored) =
            load_sequence_operation(&transaction, &request.key.tenant_id, &request.operation_id)?
        {
            validate_sequence_operation_reference(&transaction, &stored)?;
            if stored.request_hash != request_hash {
                return Err(PortError::conflict());
            }
            if stored.key != request.key
                || stored.sequence != request.sequence
                || stored.operation_id != request.operation_id
            {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(WatermarkSequenceReservationResult::ExactRetry);
        }

        let current = load_sequence_head(&transaction, &request.key)?;
        if current.is_some_and(|sequence| sequence >= request.sequence) {
            return Err(PortError::conflict());
        }
        match current {
            Some(sequence) => update_sequence_head(&transaction, request, sequence)?,
            None => insert_sequence_head(&transaction, request)?,
        }
        insert_sequence_operation(&transaction, request, &request_hash)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(WatermarkSequenceReservationResult::Reserved)
    }
}

impl WatermarkObservationStore for SqliteSealedDecoyRegistryStore {
    fn record_first(
        &self,
        observation: &WatermarkObservation,
    ) -> PortResult<WatermarkObservationResult> {
        to_i64(observation.observed_at_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;

        if let Some(stored) = load_watermark_observation(
            &transaction,
            &observation.source_tenant_id,
            &observation.public_ref_token,
            &observation.observation_id,
        )? {
            if stored != *observation {
                return Err(PortError::conflict());
            }
            let result = WatermarkObservationResult::Duplicate {
                first_payload_digest: stored.payload_digest,
                first_token_digest: stored.token_digest,
                first_evidence_ref: stored.evidence_ref,
                first_observed_at_unix_ms: stored.observed_at_unix_ms,
            };
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        }

        insert_watermark_observation(&transaction, observation)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(WatermarkObservationResult::Recorded)
    }
}

fn validate_durable_path(path: &Path) -> PortResult<()> {
    let text = path.as_os_str().to_string_lossy();
    if path.as_os_str().is_empty()
        || path == Path::new(":memory:")
        || text.to_ascii_lowercase().starts_with("file:")
        || text.contains('?')
        || text.contains('#')
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

const SEALED_DECOY_SCHEMA_SQL: &str = r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            PRAGMA trusted_schema = OFF;

            CREATE TABLE IF NOT EXISTS sealed_decoy_records_v1 (
                tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
                artifact_token BLOB NOT NULL
                    CHECK (typeof(artifact_token) = 'blob' AND length(artifact_token) = 32),
                public_ref_token BLOB
                    CHECK (
                        public_ref_token IS NULL
                        OR (typeof(public_ref_token) = 'blob' AND length(public_ref_token) = 32)
                    ),
                surface TEXT NOT NULL CHECK (
                    surface IN (
                        'canary_capability',
                        'honey_tool',
                        'credential_artifact',
                        'credential_file',
                        'file_marker',
                        'browser_cookie',
                        'internal_hostname',
                        'signed_watermark'
                    )
                ),
                marker_token BLOB NOT NULL
                    CHECK (typeof(marker_token) = 'blob' AND length(marker_token) = 32),
                version_hash BLOB NOT NULL
                    CHECK (typeof(version_hash) = 'blob' AND length(version_hash) = 32),
                generation INTEGER NOT NULL CHECK (generation >= 0),
                nonce BLOB NOT NULL CHECK (typeof(nonce) = 'blob' AND length(nonce) = 12),
                ciphertext BLOB NOT NULL CHECK (
                    typeof(ciphertext) = 'blob'
                    AND length(ciphertext) BETWEEN 1 AND 1048576
                ),
                CHECK (
                    (surface = 'signed_watermark' AND public_ref_token IS NOT NULL)
                    OR (surface <> 'signed_watermark' AND public_ref_token IS NULL)
                ),
                PRIMARY KEY (tenant_id, artifact_token),
                UNIQUE (tenant_id, surface, marker_token)
            ) STRICT, WITHOUT ROWID;

            CREATE UNIQUE INDEX IF NOT EXISTS sealed_decoy_records_public_ref_v1
                ON sealed_decoy_records_v1 (tenant_id, public_ref_token)
                WHERE public_ref_token IS NOT NULL;

            CREATE TABLE IF NOT EXISTS sealed_decoy_operation_owners_v1 (
                tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
                operation_token BLOB NOT NULL CHECK (
                    typeof(operation_token) = 'blob' AND length(operation_token) = 32
                ),
                artifact_token BLOB NOT NULL CHECK (
                    typeof(artifact_token) = 'blob' AND length(artifact_token) = 32
                ),
                PRIMARY KEY (tenant_id, operation_token),
                UNIQUE (tenant_id, operation_token, artifact_token),
                FOREIGN KEY (tenant_id, artifact_token)
                    REFERENCES sealed_decoy_records_v1 (tenant_id, artifact_token)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS sealed_decoy_transitions_v1 (
                tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
                transition_token BLOB NOT NULL CHECK (
                    typeof(transition_token) = 'blob' AND length(transition_token) = 32
                ),
                request_hash BLOB NOT NULL
                    CHECK (typeof(request_hash) = 'blob' AND length(request_hash) = 32),
                operation_token BLOB NOT NULL CHECK (
                    typeof(operation_token) = 'blob' AND length(operation_token) = 32
                ),
                result_artifact_token BLOB NOT NULL CHECK (
                    typeof(result_artifact_token) = 'blob'
                    AND length(result_artifact_token) = 32
                ),
                result_public_ref_token BLOB CHECK (
                    result_public_ref_token IS NULL
                    OR (
                        typeof(result_public_ref_token) = 'blob'
                        AND length(result_public_ref_token) = 32
                    )
                ),
                result_surface TEXT NOT NULL CHECK (
                    result_surface IN (
                        'canary_capability',
                        'honey_tool',
                        'credential_artifact',
                        'credential_file',
                        'file_marker',
                        'browser_cookie',
                        'internal_hostname',
                        'signed_watermark'
                    )
                ),
                result_marker_token BLOB NOT NULL CHECK (
                    typeof(result_marker_token) = 'blob'
                    AND length(result_marker_token) = 32
                ),
                result_version_hash BLOB NOT NULL CHECK (
                    typeof(result_version_hash) = 'blob'
                    AND length(result_version_hash) = 32
                ),
                result_generation INTEGER NOT NULL CHECK (result_generation >= 0),
                result_nonce BLOB NOT NULL CHECK (
                    typeof(result_nonce) = 'blob' AND length(result_nonce) = 12
                ),
                result_ciphertext BLOB NOT NULL CHECK (
                    typeof(result_ciphertext) = 'blob'
                    AND length(result_ciphertext) BETWEEN 1 AND 1048576
                ),
                CHECK (
                    (
                        result_surface = 'signed_watermark'
                        AND result_public_ref_token IS NOT NULL
                    )
                    OR (
                        result_surface <> 'signed_watermark'
                        AND result_public_ref_token IS NULL
                    )
                ),
                PRIMARY KEY (tenant_id, transition_token),
                FOREIGN KEY (tenant_id, result_artifact_token)
                    REFERENCES sealed_decoy_records_v1 (tenant_id, artifact_token)
                    ON UPDATE RESTRICT ON DELETE RESTRICT,
                FOREIGN KEY (tenant_id, operation_token, result_artifact_token)
                    REFERENCES sealed_decoy_operation_owners_v1 (
                        tenant_id,
                        operation_token,
                        artifact_token
                    )
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS watermark_sequence_heads_v1 (
                tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
                application_id TEXT NOT NULL CHECK (length(application_id) BETWEEN 1 AND 256),
                session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 256),
                tool_id TEXT NOT NULL CHECK (length(tool_id) BETWEEN 1 AND 256),
                public_ref_token BLOB NOT NULL CHECK (
                    typeof(public_ref_token) = 'blob' AND length(public_ref_token) = 32
                ),
                last_sequence INTEGER NOT NULL CHECK (last_sequence > 0),
                PRIMARY KEY (
                    tenant_id,
                    application_id,
                    session_id,
                    tool_id,
                    public_ref_token
                )
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS watermark_sequence_operations_v1 (
                tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
                operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 256),
                request_hash BLOB NOT NULL CHECK (
                    typeof(request_hash) = 'blob' AND length(request_hash) = 32
                ),
                application_id TEXT NOT NULL CHECK (length(application_id) BETWEEN 1 AND 256),
                session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 256),
                tool_id TEXT NOT NULL CHECK (length(tool_id) BETWEEN 1 AND 256),
                public_ref_token BLOB NOT NULL CHECK (
                    typeof(public_ref_token) = 'blob' AND length(public_ref_token) = 32
                ),
                reserved_sequence INTEGER NOT NULL CHECK (reserved_sequence > 0),
                PRIMARY KEY (tenant_id, operation_id),
                FOREIGN KEY (
                    tenant_id,
                    application_id,
                    session_id,
                    tool_id,
                    public_ref_token
                ) REFERENCES watermark_sequence_heads_v1 (
                    tenant_id,
                    application_id,
                    session_id,
                    tool_id,
                    public_ref_token
                ) ON UPDATE RESTRICT ON DELETE RESTRICT
            ) STRICT, WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS watermark_observations_v1 (
                source_tenant_id TEXT NOT NULL CHECK (
                    length(source_tenant_id) BETWEEN 1 AND 256
                ),
                public_ref_token BLOB NOT NULL CHECK (
                    typeof(public_ref_token) = 'blob' AND length(public_ref_token) = 32
                ),
                observation_id TEXT NOT NULL CHECK (length(observation_id) BETWEEN 1 AND 256),
                observing_tenant_id TEXT NOT NULL CHECK (
                    length(observing_tenant_id) BETWEEN 1 AND 256
                ),
                payload_digest BLOB NOT NULL CHECK (
                    typeof(payload_digest) = 'blob' AND length(payload_digest) = 32
                ),
                token_digest BLOB NOT NULL CHECK (
                    typeof(token_digest) = 'blob' AND length(token_digest) = 32
                ),
                evidence_ref TEXT NOT NULL CHECK (length(evidence_ref) BETWEEN 1 AND 256),
                observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms >= 0),
                PRIMARY KEY (source_tenant_id, public_ref_token, observation_id)
            ) STRICT, WITHOUT ROWID;
            "#;

fn migrate(connection: &Connection) -> PortResult<()> {
    connection
        .execute_batch(SEALED_DECOY_SCHEMA_SQL)
        .map_err(sqlite_error)
}

fn verify_runtime_configuration(connection: &Connection) -> PortResult<()> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || busy_timeout < 5_000
    {
        return Err(PortError::unavailable());
    }

    for table in [
        RECORDS_TABLE,
        OPERATIONS_TABLE,
        TRANSITIONS_TABLE,
        SEQUENCE_HEADS_TABLE,
        SEQUENCE_OPERATIONS_TABLE,
        OBSERVATIONS_TABLE,
    ] {
        let flags: Option<(i64, i64)> = connection
            .query_row(
                "SELECT wr, strict FROM pragma_table_list \
                 WHERE schema = 'main' AND name = ?1",
                [table],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        if flags != Some((1, 1)) {
            return Err(PortError::integrity_failure());
        }
    }
    for (object_type, name) in [
        ("table", RECORDS_TABLE),
        ("index", "sealed_decoy_records_public_ref_v1"),
        ("table", OPERATIONS_TABLE),
        ("table", TRANSITIONS_TABLE),
        ("table", SEQUENCE_HEADS_TABLE),
        ("table", SEQUENCE_OPERATIONS_TABLE),
        ("table", OBSERVATIONS_TABLE),
    ] {
        verify_schema_object(connection, object_type, name)?;
    }
    Ok(())
}

fn verify_schema_object(connection: &Connection, object_type: &str, name: &str) -> PortResult<()> {
    let stored: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored = stored.ok_or_else(PortError::integrity_failure)?;
    let prefix = match object_type {
        "table" => "CREATE TABLE IF NOT EXISTS ",
        "index" => "CREATE UNIQUE INDEX IF NOT EXISTS ",
        _ => return Err(PortError::integrity_failure()),
    };
    let needle = format!("{prefix}{name}");
    let start = SEALED_DECOY_SCHEMA_SQL
        .find(&needle)
        .ok_or_else(PortError::integrity_failure)?;
    let expected_tail = &SEALED_DECOY_SCHEMA_SQL[start..];
    let end = expected_tail
        .find(';')
        .ok_or_else(PortError::integrity_failure)?;
    let expected = &expected_tail[..end];
    if normalize_schema_sql(&stored) != normalize_schema_sql(expected) {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn normalize_schema_sql(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_ascii_lowercase()
        .replace(" if not exists ", " ")
}

fn validate_request(request: &SealedDecoyCasRequest) -> PortResult<()> {
    to_i64(request.record.generation)?;
    if let Some(expected) = request.expected_generation {
        to_i64(expected)?;
    }
    let ciphertext_len = request.record.encrypted_envelope.as_bytes().len();
    if ciphertext_len == 0 || ciphertext_len > MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES {
        return Err(PortError::invalid_data());
    }
    if !valid_public_ref_binding(
        request.record.surface,
        request.record.public_ref_token.as_ref(),
    ) {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_cas_state(
    current: Option<&SealedDecoyRecord>,
    request: &SealedDecoyCasRequest,
) -> PortResult<()> {
    match (current, request.expected_generation) {
        (None, None) if request.record.generation == 0 => Ok(()),
        (Some(stored), Some(expected)) => {
            let next = expected.checked_add(1).ok_or_else(PortError::conflict)?;
            if stored.generation != expected
                || request.record.generation != next
                || stored.tenant_id != request.record.tenant_id
                || stored.artifact_token != request.record.artifact_token
                || stored.public_ref_token != request.record.public_ref_token
                || stored.surface != request.record.surface
                || stored.marker_token != request.record.marker_token
                || stored.version_hash != request.record.version_hash
            {
                return Err(PortError::conflict());
            }
            Ok(())
        }
        _ => Err(PortError::conflict()),
    }
}

fn validate_unique_indexes(connection: &Connection, record: &SealedDecoyRecord) -> PortResult<()> {
    if let Some(existing) = load_record_by_marker(
        connection,
        &record.tenant_id,
        record.surface,
        &record.marker_token,
    )? {
        if existing.artifact_token != record.artifact_token {
            return Err(PortError::conflict());
        }
    }
    if let Some(public_ref_token) = record.public_ref_token {
        if let Some(existing) =
            load_record_by_public_ref(connection, &record.tenant_id, &public_ref_token)?
        {
            if existing.artifact_token != record.artifact_token {
                return Err(PortError::conflict());
            }
        }
    }
    Ok(())
}

fn insert_record(connection: &Connection, record: &SealedDecoyRecord) -> PortResult<()> {
    let public_ref_token = record
        .public_ref_token
        .as_ref()
        .map(|digest| &digest.as_bytes()[..]);
    let changed = connection
        .execute(
            r#"
            INSERT INTO sealed_decoy_records_v1 (
                tenant_id, artifact_token, public_ref_token, surface, marker_token,
                version_hash, generation, nonce, ciphertext
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                record.tenant_id.as_str(),
                &record.artifact_token.as_bytes()[..],
                public_ref_token,
                record.surface.domain_name(),
                &record.marker_token.as_bytes()[..],
                &record.version_hash.as_bytes()[..],
                to_i64(record.generation)?,
                &record.nonce.as_bytes()[..],
                record.encrypted_envelope.as_bytes(),
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn update_record(connection: &Connection, request: &SealedDecoyCasRequest) -> PortResult<()> {
    let expected = request
        .expected_generation
        .ok_or_else(PortError::conflict)?;
    let changed = connection
        .execute(
            r#"
            UPDATE sealed_decoy_records_v1
            SET generation = ?1, nonce = ?2, ciphertext = ?3
            WHERE tenant_id = ?4 AND artifact_token = ?5 AND generation = ?6
            "#,
            params![
                to_i64(request.record.generation)?,
                &request.record.nonce.as_bytes()[..],
                request.record.encrypted_envelope.as_bytes(),
                request.record.tenant_id.as_str(),
                &request.record.artifact_token.as_bytes()[..],
                to_i64(expected)?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn insert_operation_owner(
    connection: &Connection,
    tenant_id: &TenantId,
    operation_token: &Digest32,
    artifact_token: &Digest32,
) -> PortResult<()> {
    let changed = connection
        .execute(
            r#"
            INSERT INTO sealed_decoy_operation_owners_v1 (
                tenant_id, operation_token, artifact_token
            ) VALUES (?1, ?2, ?3)
            "#,
            params![
                tenant_id.as_str(),
                &operation_token.as_bytes()[..],
                &artifact_token.as_bytes()[..],
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn insert_transition(
    connection: &Connection,
    request: &SealedDecoyCasRequest,
    request_hash: &[u8; 32],
) -> PortResult<()> {
    let record = &request.record;
    let public_ref_token = record
        .public_ref_token
        .as_ref()
        .map(|digest| &digest.as_bytes()[..]);
    let changed = connection
        .execute(
            r#"
            INSERT INTO sealed_decoy_transitions_v1 (
                tenant_id, transition_token, request_hash, operation_token,
                result_artifact_token, result_public_ref_token, result_surface,
                result_marker_token, result_version_hash, result_generation,
                result_nonce, result_ciphertext
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                record.tenant_id.as_str(),
                &request.transition_token.as_bytes()[..],
                &request_hash[..],
                &request.operation_token.as_bytes()[..],
                &record.artifact_token.as_bytes()[..],
                public_ref_token,
                record.surface.domain_name(),
                &record.marker_token.as_bytes()[..],
                &record.version_hash.as_bytes()[..],
                to_i64(record.generation)?,
                &record.nonce.as_bytes()[..],
                record.encrypted_envelope.as_bytes(),
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn insert_sequence_head(
    connection: &Connection,
    request: &WatermarkSequenceReservation,
) -> PortResult<()> {
    let key = &request.key;
    let changed = connection
        .execute(
            r#"
            INSERT INTO watermark_sequence_heads_v1 (
                tenant_id, application_id, session_id, tool_id, public_ref_token, last_sequence
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                key.tenant_id.as_str(),
                key.application_id.as_str(),
                key.session_id.as_str(),
                key.tool_id.as_str(),
                &key.public_ref_token.as_bytes()[..],
                to_i64(request.sequence)?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn update_sequence_head(
    connection: &Connection,
    request: &WatermarkSequenceReservation,
    current_sequence: u64,
) -> PortResult<()> {
    let key = &request.key;
    let changed = connection
        .execute(
            r#"
            UPDATE watermark_sequence_heads_v1
            SET last_sequence = ?1
            WHERE tenant_id = ?2
              AND application_id = ?3
              AND session_id = ?4
              AND tool_id = ?5
              AND public_ref_token = ?6
              AND last_sequence = ?7
            "#,
            params![
                to_i64(request.sequence)?,
                key.tenant_id.as_str(),
                key.application_id.as_str(),
                key.session_id.as_str(),
                key.tool_id.as_str(),
                &key.public_ref_token.as_bytes()[..],
                to_i64(current_sequence)?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn insert_sequence_operation(
    connection: &Connection,
    request: &WatermarkSequenceReservation,
    request_hash: &[u8; 32],
) -> PortResult<()> {
    let key = &request.key;
    let changed = connection
        .execute(
            r#"
            INSERT INTO watermark_sequence_operations_v1 (
                tenant_id, operation_id, request_hash, application_id, session_id, tool_id,
                public_ref_token, reserved_sequence
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                key.tenant_id.as_str(),
                request.operation_id.as_str(),
                &request_hash[..],
                key.application_id.as_str(),
                key.session_id.as_str(),
                key.tool_id.as_str(),
                &key.public_ref_token.as_bytes()[..],
                to_i64(request.sequence)?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn load_sequence_head(
    connection: &Connection,
    key: &WatermarkSequenceKey,
) -> PortResult<Option<u64>> {
    let raw = connection
        .query_row(
            r#"
            SELECT tenant_id, application_id, session_id, tool_id, public_ref_token, last_sequence
            FROM watermark_sequence_heads_v1
            WHERE tenant_id = ?1
              AND application_id = ?2
              AND session_id = ?3
              AND tool_id = ?4
              AND public_ref_token = ?5
            "#,
            params![
                key.tenant_id.as_str(),
                key.application_id.as_str(),
                key.session_id.as_str(),
                key.tool_id.as_str(),
                &key.public_ref_token.as_bytes()[..],
            ],
            |row| {
                Ok(RawSequenceHead {
                    tenant_id: row.get(0)?,
                    application_id: row.get(1)?,
                    session_id: row.get(2)?,
                    tool_id: row.get(3)?,
                    public_ref_token: row.get(4)?,
                    last_sequence: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let stored = decode_sequence_head(raw)?;
    if stored.key != *key {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(stored.last_sequence))
}

fn load_sequence_operation(
    connection: &Connection,
    tenant_id: &TenantId,
    operation_id: &RecordId,
) -> PortResult<Option<StoredSequenceOperation>> {
    let raw = connection
        .query_row(
            r#"
            SELECT tenant_id, operation_id, request_hash, application_id, session_id, tool_id,
                   public_ref_token, reserved_sequence
            FROM watermark_sequence_operations_v1
            WHERE tenant_id = ?1 AND operation_id = ?2
            "#,
            params![tenant_id.as_str(), operation_id.as_str()],
            |row| {
                Ok(RawSequenceOperation {
                    tenant_id: row.get(0)?,
                    operation_id: row.get(1)?,
                    request_hash: row.get(2)?,
                    application_id: row.get(3)?,
                    session_id: row.get(4)?,
                    tool_id: row.get(5)?,
                    public_ref_token: row.get(6)?,
                    reserved_sequence: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(decode_sequence_operation).transpose()
}

fn validate_sequence_operation_reference(
    connection: &Connection,
    operation: &StoredSequenceOperation,
) -> PortResult<()> {
    let head =
        load_sequence_head(connection, &operation.key)?.ok_or_else(PortError::integrity_failure)?;
    if head < operation.sequence {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn insert_watermark_observation(
    connection: &Connection,
    observation: &WatermarkObservation,
) -> PortResult<()> {
    let changed = connection
        .execute(
            r#"
            INSERT INTO watermark_observations_v1 (
                source_tenant_id, public_ref_token, observation_id, observing_tenant_id,
                payload_digest, token_digest, evidence_ref, observed_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                observation.source_tenant_id.as_str(),
                &observation.public_ref_token.as_bytes()[..],
                observation.observation_id.as_str(),
                observation.observing_tenant_id.as_str(),
                &observation.payload_digest.as_bytes()[..],
                &observation.token_digest.as_bytes()[..],
                observation.evidence_ref.as_str(),
                to_i64(observation.observed_at_unix_ms)?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn load_watermark_observation(
    connection: &Connection,
    source_tenant_id: &TenantId,
    public_ref_token: &Digest32,
    observation_id: &RecordId,
) -> PortResult<Option<WatermarkObservation>> {
    let raw = connection
        .query_row(
            r#"
            SELECT source_tenant_id, observing_tenant_id, public_ref_token, observation_id,
                   payload_digest, token_digest, evidence_ref, observed_at_unix_ms
            FROM watermark_observations_v1
            WHERE source_tenant_id = ?1
              AND public_ref_token = ?2
              AND observation_id = ?3
            "#,
            params![
                source_tenant_id.as_str(),
                &public_ref_token.as_bytes()[..],
                observation_id.as_str(),
            ],
            |row| {
                Ok(RawWatermarkObservation {
                    source_tenant_id: row.get(0)?,
                    observing_tenant_id: row.get(1)?,
                    public_ref_token: row.get(2)?,
                    observation_id: row.get(3)?,
                    payload_digest: row.get(4)?,
                    token_digest: row.get(5)?,
                    evidence_ref: row.get(6)?,
                    observed_at_unix_ms: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(decode_watermark_observation).transpose()
}

fn load_record_by_id(
    connection: &Connection,
    tenant_id: &TenantId,
    artifact_token: &Digest32,
) -> PortResult<Option<SealedDecoyRecord>> {
    let raw = connection
        .query_row(
            r#"
            SELECT tenant_id, artifact_token, public_ref_token, surface, marker_token,
                   version_hash, generation, nonce, ciphertext
            FROM sealed_decoy_records_v1
            WHERE tenant_id = ?1 AND artifact_token = ?2
            "#,
            params![tenant_id.as_str(), &artifact_token.as_bytes()[..]],
            raw_record_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(decode_record).transpose()
}

fn load_record_by_marker(
    connection: &Connection,
    tenant_id: &TenantId,
    surface: DecoySurface,
    marker_token: &Digest32,
) -> PortResult<Option<SealedDecoyRecord>> {
    let raw = connection
        .query_row(
            r#"
            SELECT tenant_id, artifact_token, public_ref_token, surface, marker_token,
                   version_hash, generation, nonce, ciphertext
            FROM sealed_decoy_records_v1
            WHERE tenant_id = ?1 AND surface = ?2 AND marker_token = ?3
            "#,
            params![
                tenant_id.as_str(),
                surface.domain_name(),
                &marker_token.as_bytes()[..]
            ],
            raw_record_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(decode_record).transpose()
}

fn load_record_by_public_ref(
    connection: &Connection,
    tenant_id: &TenantId,
    public_ref_token: &Digest32,
) -> PortResult<Option<SealedDecoyRecord>> {
    let raw = connection
        .query_row(
            r#"
            SELECT tenant_id, artifact_token, public_ref_token, surface, marker_token,
                   version_hash, generation, nonce, ciphertext
            FROM sealed_decoy_records_v1
            WHERE tenant_id = ?1 AND public_ref_token = ?2
            "#,
            params![tenant_id.as_str(), &public_ref_token.as_bytes()[..]],
            raw_record_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(decode_record).transpose()
}

fn load_operation_owner(
    connection: &Connection,
    tenant_id: &TenantId,
    operation_token: &Digest32,
) -> PortResult<Option<Digest32>> {
    let raw: Option<Vec<u8>> = connection
        .query_row(
            r#"
            SELECT artifact_token
            FROM sealed_decoy_operation_owners_v1
            WHERE tenant_id = ?1 AND operation_token = ?2
            "#,
            params![tenant_id.as_str(), &operation_token.as_bytes()[..]],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(decode_digest).transpose()
}

fn load_transition(
    connection: &Connection,
    tenant_id: &TenantId,
    transition_token: &Digest32,
) -> PortResult<Option<StoredTransition>> {
    let raw = connection
        .query_row(
            r#"
            SELECT request_hash, operation_token, tenant_id, result_artifact_token,
                   result_public_ref_token, result_surface, result_marker_token,
                   result_version_hash, result_generation, result_nonce, result_ciphertext
            FROM sealed_decoy_transitions_v1
            WHERE tenant_id = ?1 AND transition_token = ?2
            "#,
            params![tenant_id.as_str(), &transition_token.as_bytes()[..]],
            |row| {
                Ok(RawTransition {
                    request_hash: row.get(0)?,
                    operation_token: row.get(1)?,
                    result: RawRecord {
                        tenant_id: row.get(2)?,
                        artifact_token: row.get(3)?,
                        public_ref_token: row.get(4)?,
                        surface: row.get(5)?,
                        marker_token: row.get(6)?,
                        version_hash: row.get(7)?,
                        generation: row.get(8)?,
                        nonce: row.get(9)?,
                        ciphertext: row.get(10)?,
                    },
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(decode_transition).transpose()
}

fn validate_transition_references(
    connection: &Connection,
    transition: &StoredTransition,
) -> PortResult<()> {
    let owner = load_operation_owner(
        connection,
        &transition.result.tenant_id,
        &transition.operation_token,
    )?
    .ok_or_else(PortError::integrity_failure)?;
    if owner != transition.result.artifact_token {
        return Err(PortError::integrity_failure());
    }
    let current = load_record_by_id(
        connection,
        &transition.result.tenant_id,
        &transition.result.artifact_token,
    )?
    .ok_or_else(PortError::integrity_failure)?;
    if current.tenant_id != transition.result.tenant_id
        || current.artifact_token != transition.result.artifact_token
        || current.public_ref_token != transition.result.public_ref_token
        || current.surface != transition.result.surface
        || current.marker_token != transition.result.marker_token
        || current.version_hash != transition.result.version_hash
        || current.generation < transition.result.generation
        || (current.generation == transition.result.generation && current != transition.result)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn collect_raw_records(mut rows: Rows<'_>) -> PortResult<Vec<RawRecord>> {
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        records.push(raw_record_from_row(row).map_err(sqlite_error)?);
    }
    Ok(records)
}

fn raw_record_from_row(row: &Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        tenant_id: row.get(0)?,
        artifact_token: row.get(1)?,
        public_ref_token: row.get(2)?,
        surface: row.get(3)?,
        marker_token: row.get(4)?,
        version_hash: row.get(5)?,
        generation: row.get(6)?,
        nonce: row.get(7)?,
        ciphertext: row.get(8)?,
    })
}

struct RawRecord {
    tenant_id: String,
    artifact_token: Vec<u8>,
    public_ref_token: Option<Vec<u8>>,
    surface: String,
    marker_token: Vec<u8>,
    version_hash: Vec<u8>,
    generation: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

struct RawTransition {
    request_hash: Vec<u8>,
    operation_token: Vec<u8>,
    result: RawRecord,
}

struct StoredTransition {
    request_hash: [u8; 32],
    operation_token: Digest32,
    result: SealedDecoyRecord,
}

struct RawSequenceHead {
    tenant_id: String,
    application_id: String,
    session_id: String,
    tool_id: String,
    public_ref_token: Vec<u8>,
    last_sequence: i64,
}

struct StoredSequenceHead {
    key: WatermarkSequenceKey,
    last_sequence: u64,
}

struct RawSequenceOperation {
    tenant_id: String,
    operation_id: String,
    request_hash: Vec<u8>,
    application_id: String,
    session_id: String,
    tool_id: String,
    public_ref_token: Vec<u8>,
    reserved_sequence: i64,
}

struct StoredSequenceOperation {
    key: WatermarkSequenceKey,
    operation_id: RecordId,
    request_hash: [u8; 32],
    sequence: u64,
}

struct RawWatermarkObservation {
    source_tenant_id: String,
    observing_tenant_id: String,
    public_ref_token: Vec<u8>,
    observation_id: String,
    payload_digest: Vec<u8>,
    token_digest: Vec<u8>,
    evidence_ref: String,
    observed_at_unix_ms: i64,
}

fn decode_record(raw: RawRecord) -> PortResult<SealedDecoyRecord> {
    if raw.ciphertext.is_empty() || raw.ciphertext.len() > MAX_ENCRYPTED_DECOY_ENVELOPE_BYTES {
        return Err(PortError::integrity_failure());
    }
    let tenant_id = TenantId::new(raw.tenant_id).map_err(|_| PortError::integrity_failure())?;
    let artifact_token = decode_digest(raw.artifact_token)?;
    let public_ref_token = raw.public_ref_token.map(decode_digest).transpose()?;
    let surface = decode_surface(&raw.surface)?;
    if !valid_public_ref_binding(surface, public_ref_token.as_ref()) {
        return Err(PortError::integrity_failure());
    }
    let marker_token = decode_digest(raw.marker_token)?;
    let version_hash = decode_digest(raw.version_hash)?;
    let generation = u64::try_from(raw.generation).map_err(|_| PortError::integrity_failure())?;
    let nonce = DecoyAeadNonce::new(decode_array(raw.nonce)?);
    let encrypted_envelope =
        EncryptedDecoyEnvelope::new(raw.ciphertext).map_err(|_| PortError::integrity_failure())?;
    Ok(SealedDecoyRecord {
        tenant_id,
        artifact_token,
        public_ref_token,
        surface,
        marker_token,
        version_hash,
        generation,
        nonce,
        encrypted_envelope,
    })
}

fn decode_transition(raw: RawTransition) -> PortResult<StoredTransition> {
    Ok(StoredTransition {
        request_hash: decode_array(raw.request_hash)?,
        operation_token: decode_digest(raw.operation_token)?,
        result: decode_record(raw.result)?,
    })
}

fn decode_sequence_head(raw: RawSequenceHead) -> PortResult<StoredSequenceHead> {
    let last_sequence =
        u64::try_from(raw.last_sequence).map_err(|_| PortError::integrity_failure())?;
    if last_sequence == 0 {
        return Err(PortError::integrity_failure());
    }
    Ok(StoredSequenceHead {
        key: WatermarkSequenceKey {
            tenant_id: TenantId::new(raw.tenant_id).map_err(|_| PortError::integrity_failure())?,
            application_id: decode_record_id(raw.application_id)?,
            session_id: decode_record_id(raw.session_id)?,
            tool_id: decode_record_id(raw.tool_id)?,
            public_ref_token: decode_digest(raw.public_ref_token)?,
        },
        last_sequence,
    })
}

fn decode_sequence_operation(raw: RawSequenceOperation) -> PortResult<StoredSequenceOperation> {
    let sequence =
        u64::try_from(raw.reserved_sequence).map_err(|_| PortError::integrity_failure())?;
    if sequence == 0 {
        return Err(PortError::integrity_failure());
    }
    Ok(StoredSequenceOperation {
        key: WatermarkSequenceKey {
            tenant_id: TenantId::new(raw.tenant_id).map_err(|_| PortError::integrity_failure())?,
            application_id: decode_record_id(raw.application_id)?,
            session_id: decode_record_id(raw.session_id)?,
            tool_id: decode_record_id(raw.tool_id)?,
            public_ref_token: decode_digest(raw.public_ref_token)?,
        },
        operation_id: decode_record_id(raw.operation_id)?,
        request_hash: decode_array(raw.request_hash)?,
        sequence,
    })
}

fn decode_watermark_observation(raw: RawWatermarkObservation) -> PortResult<WatermarkObservation> {
    Ok(WatermarkObservation {
        source_tenant_id: TenantId::new(raw.source_tenant_id)
            .map_err(|_| PortError::integrity_failure())?,
        observing_tenant_id: TenantId::new(raw.observing_tenant_id)
            .map_err(|_| PortError::integrity_failure())?,
        public_ref_token: decode_digest(raw.public_ref_token)?,
        observation_id: decode_record_id(raw.observation_id)?,
        payload_digest: decode_digest(raw.payload_digest)?,
        token_digest: decode_digest(raw.token_digest)?,
        evidence_ref: decode_record_id(raw.evidence_ref)?,
        observed_at_unix_ms: u64::try_from(raw.observed_at_unix_ms)
            .map_err(|_| PortError::integrity_failure())?,
    })
}

fn decode_record_id(value: String) -> PortResult<RecordId> {
    RecordId::new(value).map_err(|_| PortError::integrity_failure())
}

fn decode_digest(bytes: Vec<u8>) -> PortResult<Digest32> {
    Ok(Digest32::new(decode_array(bytes)?))
}

fn decode_array<const N: usize>(bytes: Vec<u8>) -> PortResult<[u8; N]> {
    bytes.try_into().map_err(|_| PortError::integrity_failure())
}

fn decode_surface(value: &str) -> PortResult<DecoySurface> {
    match value {
        "canary_capability" => Ok(DecoySurface::CanaryCapability),
        "honey_tool" => Ok(DecoySurface::HoneyTool),
        "credential_artifact" => Ok(DecoySurface::CredentialArtifact),
        "credential_file" => Ok(DecoySurface::CredentialFile),
        "file_marker" => Ok(DecoySurface::FileMarker),
        "browser_cookie" => Ok(DecoySurface::BrowserCookie),
        "internal_hostname" => Ok(DecoySurface::InternalHostname),
        "signed_watermark" => Ok(DecoySurface::SignedWatermark),
        _ => Err(PortError::integrity_failure()),
    }
}

fn valid_public_ref_binding(surface: DecoySurface, public_ref_token: Option<&Digest32>) -> bool {
    matches!(
        (surface, public_ref_token),
        (DecoySurface::SignedWatermark, Some(_))
    ) || (surface != DecoySurface::SignedWatermark && public_ref_token.is_none())
}

fn canonical_request_hash<T: serde::Serialize>(value: &T) -> PortResult<[u8; 32]> {
    let canonical = canonical_json_bytes(value).map_err(|_| PortError::invalid_data())?;
    let hash = sha256(canonical.as_ref());
    let mut result = [0_u8; 32];
    result.copy_from_slice(hash.as_ref());
    Ok(result)
}

fn to_i64(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

fn sqlite_error(error: rusqlite::Error) -> PortError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            PortError::conflict()
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseCorrupt
                    | rusqlite::ErrorCode::NotADatabase
                    | rusqlite::ErrorCode::TypeMismatch
            ) =>
        {
            PortError::integrity_failure()
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::Utf8Error(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::QueryReturnedNoRows
        | rusqlite::Error::QueryReturnedMoreThanOneRow => PortError::integrity_failure(),
        rusqlite::Error::ToSqlConversionFailure(_) => PortError::invalid_data(),
        _ => PortError::unavailable(),
    }
}
