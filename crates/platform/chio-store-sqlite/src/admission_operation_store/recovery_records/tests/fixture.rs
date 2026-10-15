//! A real record catalog seeded through exact SQL with v1 digests.

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{params, Connection, OptionalExtension};

use super::super::digest::{event_digest, record_digest, EventDigestInput, RecordDigestInput};
use super::super::global_coverage::RECOVERY_MUTATION_KIND;
use super::super::{NativeIdentity, RecordKind, GENESIS_DIGEST};

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

const RECORDS: &str = include_str!("../../../admission_operation_recovery.sql");

/// The columns of the global commit catalog that recovery coverage reads.
const GLOBAL_COMMITS: &str = "
    CREATE TABLE authority_global_commits (
        commit_sequence INTEGER PRIMARY KEY,
        mutation_kind TEXT NOT NULL,
        projection_kind TEXT NOT NULL,
        projection_key TEXT NOT NULL,
        projection_sequence INTEGER NOT NULL,
        projection_reference_digest TEXT NOT NULL
    );
    CREATE INDEX authority_global_commits_projection
        ON authority_global_commits(projection_kind, projection_key, projection_sequence);";

pub(super) const SCOPE: &str = "abababababababababababababababababababababababababababababababab";

pub(super) struct Published {
    pub event_digest: String,
}

pub(super) struct EventSeed<'a> {
    pub sequence: u64,
    pub key: &'a str,
    pub version: u64,
    pub record_digest: &'a str,
    pub previous: &'a str,
    pub observed: u64,
}

pub(super) struct Ledger {
    pub connection: Connection,
    head: String,
    sequence: u64,
    observed: u64,
}

impl Ledger {
    pub(super) fn new() -> rusqlite::Result<Self> {
        Self::with_encoding("UTF-8")
    }

    pub(super) fn with_encoding(encoding: &str) -> rusqlite::Result<Self> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "encoding", encoding)?;
        connection.execute_batch(RECORDS)?;
        let actual: String = connection.pragma_query_value(None, "encoding", |row| row.get(0))?;
        assert_eq!(actual, encoding);
        Ok(Self {
            connection,
            head: GENESIS_DIGEST.to_owned(),
            sequence: 0,
            observed: 0,
        })
    }

    pub(super) fn head(&self) -> &str {
        &self.head
    }

    pub(super) fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Write the next version of a record and append its exact event.
    pub(super) fn publish(
        &mut self,
        key: &str,
        kind: RecordKind,
        payload: &[u8],
        native: Option<&NativeIdentity>,
    ) -> Result<Published, Box<dyn std::error::Error>> {
        self.publish_in(SCOPE, key, kind, payload, native)
    }

    pub(super) fn publish_in(
        &mut self,
        scope: &str,
        key: &str,
        kind: RecordKind,
        payload: &[u8],
        native: Option<&NativeIdentity>,
    ) -> Result<Published, Box<dyn std::error::Error>> {
        let version = self.write_record(scope, key, kind, payload, native)?;
        let digest = record_digest(&RecordDigestInput {
            key,
            scope,
            kind,
            version,
            payload,
            native,
        })?;
        let head = self.head.clone();
        self.append_event(&EventSeed {
            sequence: self.sequence + 1,
            key,
            version,
            record_digest: &digest,
            previous: &head,
            observed: self.observed + 1,
        })
    }

    /// Write the next record version without any event.
    pub(super) fn write_record(
        &self,
        scope: &str,
        key: &str,
        kind: RecordKind,
        payload: &[u8],
        native: Option<&NativeIdentity>,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let namespace = native.map(|native| native.namespace.as_str());
        let request = native.map(|native| native.request.as_str());
        let current: Option<i64> = self
            .connection
            .query_row(
                "SELECT version FROM admission_operation_recovery_records WHERE record_key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()?;
        let Some(current) = current else {
            self.connection.execute(
                "INSERT INTO admission_operation_recovery_records
                 (record_key, scope_key, kind, version, payload, native_namespace, native_request)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
                params![key, scope, kind.as_str(), payload, namespace, request],
            )?;
            return Ok(1);
        };
        let next = current + 1;
        self.connection.execute(
            "UPDATE admission_operation_recovery_records
             SET version = ?2, payload = ?3, native_namespace = ?4, native_request = ?5
             WHERE record_key = ?1",
            params![key, next, payload, namespace, request],
        )?;
        Ok(u64::try_from(next)?)
    }

    /// Record digest of the record's current row, as `publish` binds it.
    pub(super) fn current_digest(
        &self,
        key: &str,
        kind: RecordKind,
        payload: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let version: i64 = self.connection.query_row(
            "SELECT version FROM admission_operation_recovery_records WHERE record_key = ?1",
            [key],
            |row| row.get(0),
        )?;
        Ok(record_digest(&RecordDigestInput {
            key,
            scope: SCOPE,
            kind,
            version: u64::try_from(version)?,
            payload,
            native: None,
        })?)
    }

    /// Append an event with its correct v1 digest.
    pub(super) fn append_event(
        &mut self,
        seed: &EventSeed<'_>,
    ) -> Result<Published, Box<dyn std::error::Error>> {
        let digest = event_digest(&EventDigestInput {
            sequence: seed.sequence,
            key: seed.key,
            version: seed.version,
            record_digest: seed.record_digest,
            previous_digest: seed.previous,
            observed_at: seed.observed,
        })?;
        self.append_event_with_digest(seed, &digest)
    }

    /// Append an event storing `stored_digest` whatever its fields digest to.
    pub(super) fn append_event_with_digest(
        &mut self,
        seed: &EventSeed<'_>,
        stored_digest: &str,
    ) -> Result<Published, Box<dyn std::error::Error>> {
        self.connection.execute(
            "INSERT INTO admission_operation_recovery_events
             (sequence, record_key, record_version, record_digest, previous_digest,
              event_digest, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                i64::try_from(seed.sequence)?,
                seed.key,
                i64::try_from(seed.version)?,
                seed.record_digest,
                seed.previous,
                stored_digest,
                i64::try_from(seed.observed)?
            ],
        )?;
        self.head = stored_digest.to_owned();
        self.sequence = seed.sequence;
        self.observed = seed.observed;
        Ok(Published {
            event_digest: stored_digest.to_owned(),
        })
    }

    /// Remove a catalog guard to simulate damage written outside the store.
    pub(super) fn drop_guard(&self, trigger: &str) -> rusqlite::Result<()> {
        self.connection.execute_batch(&format!(
            "PRAGMA foreign_keys = OFF; DROP TRIGGER {trigger};"
        ))
    }

    /// Disable catalog CHECK enforcement (and foreign keys) to write values the
    /// catalog refuses; `true` restores CHECK enforcement before any read.
    pub(super) fn set_checks(&self, enforced: bool) -> rusqlite::Result<()> {
        if enforced {
            self.connection
                .execute_batch("PRAGMA ignore_check_constraints = OFF;")
        } else {
            self.connection
                .execute_batch("PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON;")
        }
    }

    pub(super) fn checks_enforced(&self) -> rusqlite::Result<bool> {
        self.connection
            .query_row("PRAGMA ignore_check_constraints", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|ignored| ignored == 0)
    }

    pub(super) fn install_global_commits(&self) -> rusqlite::Result<()> {
        self.connection.execute_batch(GLOBAL_COMMITS)
    }

    pub(super) fn commit(
        &self,
        commit_sequence: i64,
        key: &str,
        version: u64,
        reference: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.commit_as(
            RECOVERY_MUTATION_KIND,
            commit_sequence,
            key,
            version,
            reference,
        )
    }

    pub(super) fn commit_as(
        &self,
        mutation_kind: &str,
        commit_sequence: i64,
        key: &str,
        version: u64,
        reference: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.connection.execute(
            "INSERT INTO authority_global_commits
             (commit_sequence, mutation_kind, projection_kind, projection_key,
              projection_sequence, projection_reference_digest)
             VALUES (?1, ?2, 'recovery', ?3, ?4, ?5)",
            params![
                commit_sequence,
                mutation_kind,
                key,
                i64::try_from(version)?,
                reference
            ],
        )?;
        Ok(())
    }
}

pub(super) fn assert_refused<T: std::fmt::Debug>(
    result: Result<T, AdmissionOperationStoreError>,
    expected: &str,
) {
    match result {
        Err(AdmissionOperationStoreError::Invariant(detail)) => assert_eq!(detail, expected),
        other => panic!("expected refusal {expected:?}, got {other:?}"),
    }
}
