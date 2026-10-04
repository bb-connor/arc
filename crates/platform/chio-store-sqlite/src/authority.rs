use std::path::Path;
use std::sync::Mutex;

use crate::budget_store::{
    budget_snapshot_anchor_chain_digest, BudgetSnapshotAnchorCommitment,
    SignedBudgetSnapshotAnchorCommitment,
};
use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{Keypair, PublicKey, Signature};
use chio_kernel::{
    ensure_capability_issuance_supported, AuthoritySnapshot, AuthorityStatus, AuthorityStoreError,
    AuthorityTrustedKeySnapshot, CapabilityAuthority, KernelError,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

mod boundaries;
mod custody;
mod lifecycle;
mod replication;
use boundaries::*;

#[cfg(test)]
mod transaction_tests;

pub struct SqliteCapabilityAuthority {
    clock: crate::store_clock::StoreClock,
    custody: custody::AuthorityCustody,
    cached_public_key: Mutex<PublicKey>,
}

/// Authority-store schema revision. Bump on every schema-affecting change.
const AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 3;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const AUTHORITY_STORE_SCHEMA_KEY: &str = "authority";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// authority database rather than reject it as foreign.
const AUTHORITY_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["authority_state"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityClusterFence {
    pub leader_url: Option<String>,
    pub election_term: u64,
    pub updated_at: u64,
    pub authority_generation: u64,
    pub authority_rotated_at: u64,
}

impl SqliteCapabilityAuthority {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuthorityStoreError> {
        Self::open_with_clock(
            path,
            std::sync::Arc::new(chio_security_types::clock::SystemClock),
        )
    }

    pub fn open_with_clock(
        path: impl AsRef<Path>,
        clock: std::sync::Arc<dyn chio_security_types::clock::Clock>,
    ) -> Result<Self, AuthorityStoreError> {
        let custody = custody::AuthorityCustody::prepare(path.as_ref())?;

        let clock = crate::store_clock::StoreClock::new(clock);
        let bootstrap = Keypair::generate();
        let bootstrap_time = clock.unix_millis()?;
        let bootstrap_at = bootstrap_time.as_secs();
        let mut connection = Self::open_connection(&custody)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            r#"
            INSERT INTO authority_state (singleton_id, seed_hex, public_key_hex, generation, rotated_at)
            VALUES (1, ?1, ?2, 1, ?3)
            ON CONFLICT(singleton_id) DO NOTHING
            "#,
            params![
                bootstrap.seed_hex(),
                bootstrap.public_key().to_hex(),
                authority_sqlite_integer(bootstrap_at, "rotation time")?
            ],
        )?;
        let current_public_key = transaction
            .query_row(
                r#"
                SELECT seed_hex
                FROM authority_state
                WHERE singleton_id = 1
                "#,
                [],
                |row| row.get::<_, String>(0),
            )
            .map(|seed_hex| Keypair::from_seed_hex(seed_hex.trim()))
            .map_err(AuthorityStoreError::from)??;
        transaction.execute(
            r#"
            UPDATE authority_state
            SET public_key_hex = COALESCE(NULLIF(public_key_hex, ''), ?1)
            WHERE singleton_id = 1
            "#,
            params![current_public_key.public_key().to_hex()],
        )?;
        if inserted != 0 {
            transaction.execute(
                r#"
            INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at)
            VALUES (?1, 1, ?2)
            ON CONFLICT(public_key_hex) DO NOTHING
            "#,
                params![
                    current_public_key.public_key().to_hex(),
                    authority_sqlite_integer(bootstrap_at, "rotation time")?
                ],
            )?;
        }
        let status = Self::read_status_from_connection(&transaction)?;
        // An interrupted legacy bootstrap is not evidence of issuer trust.
        // In particular, never repair this by inserting a follower's local key.
        if !status.trusted_public_keys.contains(&status.public_key) {
            return Err(AuthorityStoreError::Schema(
                "authority head is absent from persisted issuer history; restore an authenticated backup before reopening".into(),
            ));
        }
        lifecycle::observe_time(&transaction, bootstrap_time)?;
        custody.validate(&transaction)?;
        transaction.commit()?;
        Ok(Self {
            clock,
            custody,
            cached_public_key: Mutex::new(status.public_key),
        })
    }

    pub fn status(&self) -> Result<AuthorityStatus, AuthorityStoreError> {
        let mut connection = Self::open_connection(&self.custody)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = self.clock.unix_millis()?;
        lifecycle::observe_time(&transaction, now)?;
        let snapshot = replication::read_snapshot(&transaction)?;
        let mut status = Self::read_status_from_connection(&transaction)?;
        status.trusted_public_keys = lifecycle::live_public_keys(&snapshot, now.as_secs())?;
        transaction.commit()?;
        self.update_cached_public_key(status.public_key.clone());
        Ok(status)
    }

    pub fn rotate(&self) -> Result<AuthorityStatus, AuthorityStoreError> {
        self.mutate_lifecycle(None, None)
    }

    pub fn snapshot(&self) -> Result<AuthoritySnapshot, AuthorityStoreError> {
        let mut connection = Self::open_connection(&self.custody)?;
        let transaction = connection.transaction()?;
        let (public_key, generation, rotated_at) =
            Self::read_public_state_from_connection(&transaction)?;
        let snapshot = AuthoritySnapshot {
            public_key_hex: public_key.to_hex(),
            generation,
            rotated_at,
            trusted_keys: Self::read_trusted_key_snapshots(&transaction)?,
        };
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Unsigned import was never an authority grant. Retained to reject legacy callers.
    pub fn apply_snapshot(
        &self,
        _snapshot: &AuthoritySnapshot,
    ) -> Result<bool, AuthorityStoreError> {
        Err(AuthorityStoreError::Fence(
            "unsigned authority snapshot".to_string(),
        ))
    }

    pub fn current_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        self.read_current_keypair()
    }

    pub fn local_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        let connection = Self::open_connection(&self.custody)?;
        Self::read_keypair_from_connection(&connection)
    }

    pub fn commit_budget_snapshot_anchor_set(
        &self,
        anchor_set_digest: &str,
        leader_url: &str,
        election_term: u64,
        committed_at: u64,
    ) -> Result<Vec<SignedBudgetSnapshotAnchorCommitment>, AuthorityStoreError> {
        if anchor_set_digest.len() != 64
            || !anchor_set_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || leader_url.is_empty()
            || election_term == 0
        {
            return Err(AuthorityStoreError::Fence(
                "budget snapshot anchor commitment identity is invalid".to_string(),
            ));
        }
        let election_term_sqlite = i64::try_from(election_term).map_err(|_| {
            AuthorityStoreError::Fence(
                "budget snapshot anchor election term exceeds SQLite range".to_string(),
            )
        })?;
        let committed_at_sqlite = i64::try_from(committed_at).map_err(|_| {
            AuthorityStoreError::Fence(
                "budget snapshot anchor commit time exceeds SQLite range".to_string(),
            )
        })?;
        let mut connection = Self::open_connection(&self.custody)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        lifecycle::observe_time(&transaction, self.clock.unix_millis()?)?;
        chio_kernel::authority::replication::validate_state(&replication::read_snapshot(
            &transaction,
        )?)?;
        let keypair = Self::read_keypair_from_connection(&transaction)?;
        let signer_public_key = keypair.public_key().to_hex();
        let latest = transaction
            .query_row(
                r#"
                SELECT commit_sequence, anchor_set_digest, leader_url, election_term,
                       signer_public_key
                FROM authority_budget_anchor_commits
                ORDER BY commit_sequence DESC LIMIT 1
                "#,
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let already_committed = latest
            .as_ref()
            .is_some_and(|(_, digest, leader, term, signer)| {
                digest == anchor_set_digest
                    && leader == leader_url
                    && *term == election_term_sqlite
                    && signer == &signer_public_key
            });
        if !already_committed {
            let (previous_sequence, previous_chain_digest) = transaction
                .query_row(
                    r#"
                    SELECT commit_sequence, chain_digest
                    FROM authority_budget_anchor_commits
                    ORDER BY commit_sequence DESC LIMIT 1
                    "#,
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .unwrap_or((
                    0,
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ));
            let commit_sequence = u64::try_from(previous_sequence)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    AuthorityStoreError::Fence(
                        "budget snapshot anchor commitment sequence overflowed".to_string(),
                    )
                })?;
            let mut body = BudgetSnapshotAnchorCommitment {
                schema: "chio.budget-snapshot-anchor-commitment.v1".to_string(),
                commit_sequence,
                previous_chain_digest,
                chain_digest: String::new(),
                anchor_set_digest: anchor_set_digest.to_string(),
                leader_url: leader_url.to_string(),
                election_term,
                committed_at,
                signer_public_key,
            };
            body.chain_digest = budget_snapshot_anchor_chain_digest(&body)
                .map_err(|error| AuthorityStoreError::Fence(error.to_string()))?;
            let signature = keypair
                .sign_canonical(&body)
                .map_err(|error| AuthorityStoreError::Fence(error.to_string()))?
                .0;
            let commit_sequence_sqlite = i64::try_from(commit_sequence).map_err(|_| {
                AuthorityStoreError::Fence(
                    "budget snapshot anchor commitment sequence exceeds SQLite range".to_string(),
                )
            })?;
            transaction.execute(
                r#"
                INSERT INTO authority_budget_anchor_commits (
                    commit_sequence, previous_chain_digest, chain_digest,
                    anchor_set_digest, leader_url, election_term, committed_at,
                    signer_public_key, signature
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    commit_sequence_sqlite,
                    &body.previous_chain_digest,
                    &body.chain_digest,
                    &body.anchor_set_digest,
                    &body.leader_url,
                    election_term_sqlite,
                    committed_at_sqlite,
                    &body.signer_public_key,
                    signature.to_hex(),
                ],
            )?;
        }
        let chain = Self::read_budget_anchor_commit_chain(&transaction)?;
        transaction.commit()?;
        Ok(chain)
    }

    pub fn cluster_fence(&self) -> Result<AuthorityClusterFence, AuthorityStoreError> {
        let connection = Self::open_connection(&self.custody)?;
        Self::read_cluster_fence_from_connection(&connection)
    }

    pub fn seed_cluster_fence(
        &self,
        leader_url: Option<&str>,
        election_term: u64,
    ) -> Result<bool, AuthorityStoreError> {
        authority_sqlite_integer(election_term, "election term")?;
        let mut connection = Self::open_connection(&self.custody)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = Self::read_cluster_fence_from_connection(&transaction)?;
        let (_, authority_generation, authority_rotated_at) =
            Self::read_public_state_from_connection(&transaction)?;
        let next_leader = leader_url.map(ToOwned::to_owned);
        let same_term_same_leader = election_term == current.election_term
            && current.leader_url.as_deref() == next_leader.as_deref();
        let fence_authority_state_is_stale = (current.election_term > 0
            || current.leader_url.is_some())
            && (current.authority_generation != authority_generation
                || current.authority_rotated_at != authority_rotated_at);
        let should_update = election_term > current.election_term
            || (election_term == current.election_term
                && current.leader_url.is_none()
                && next_leader.is_some())
            || (same_term_same_leader && fence_authority_state_is_stale);
        if should_update {
            Self::write_cluster_fence_to_connection(
                &transaction,
                next_leader,
                election_term,
                self.clock.unix_millis()?.as_secs(),
            )?;
        }
        transaction.commit()?;
        Ok(should_update)
    }

    pub fn enforce_cluster_fence(
        &self,
        leader_url: &str,
        election_term: u64,
    ) -> Result<(), AuthorityStoreError> {
        authority_sqlite_integer(election_term, "election term")?;
        let mut connection = Self::open_connection(&self.custody)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = Self::read_cluster_fence_from_connection(&transaction)?;
        let (_, authority_generation, authority_rotated_at) =
            Self::read_public_state_from_connection(&transaction)?;
        if (current.election_term > 0 || current.leader_url.is_some())
            && (current.authority_generation != authority_generation
                || current.authority_rotated_at != authority_rotated_at)
        {
            return Err(AuthorityStoreError::Fence(format!(
                "persisted authority fence generation `{}` rotated_at `{}` does not match current authority generation `{authority_generation}` rotated_at `{authority_rotated_at}`",
                current.authority_generation, current.authority_rotated_at
            )));
        }
        if election_term < current.election_term {
            return Err(AuthorityStoreError::Fence(format!(
                "stale authority term `{election_term}` is below persisted term `{}`",
                current.election_term
            )));
        }
        if election_term == current.election_term
            && current
                .leader_url
                .as_deref()
                .is_some_and(|current_leader| current_leader != leader_url)
        {
            return Err(AuthorityStoreError::Fence(format!(
                "authority term `{election_term}` is already fenced to leader `{}`",
                current.leader_url.unwrap_or_default()
            )));
        }
        Self::write_cluster_fence_to_connection(
            &transaction,
            Some(leader_url.to_string()),
            election_term,
            self.clock.unix_millis()?.as_secs(),
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn open_connection(
        custody: &custody::AuthorityCustody,
    ) -> Result<Connection, AuthorityStoreError> {
        let connection = custody.open_connection()?;
        crate::check_schema_version(
            &connection,
            AUTHORITY_STORE_SCHEMA_KEY,
            AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION,
            AUTHORITY_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| AuthorityStoreError::Schema(error.to_string()))?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS authority_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                seed_hex TEXT NOT NULL,
                public_key_hex TEXT,
                generation INTEGER NOT NULL,
                rotated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authority_trusted_keys (
                public_key_hex TEXT PRIMARY KEY,
                generation INTEGER NOT NULL,
                activated_at INTEGER NOT NULL,
                lifecycle_json TEXT
            );

            CREATE TABLE IF NOT EXISTS authority_cluster_fence (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                leader_url TEXT,
                election_term INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                authority_generation INTEGER NOT NULL DEFAULT 0,
                authority_rotated_at INTEGER NOT NULL DEFAULT 0
            );

            INSERT INTO authority_cluster_fence (singleton_id, leader_url, election_term, updated_at)
            VALUES (1, NULL, 0, 0)
            ON CONFLICT(singleton_id) DO NOTHING;

            CREATE TABLE IF NOT EXISTS authority_budget_anchor_commits (
                commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
                previous_chain_digest TEXT NOT NULL,
                chain_digest TEXT NOT NULL UNIQUE,
                anchor_set_digest TEXT NOT NULL,
                leader_url TEXT NOT NULL CHECK (leader_url <> ''),
                election_term INTEGER NOT NULL CHECK (election_term > 0),
                committed_at INTEGER NOT NULL CHECK (committed_at >= 0),
                signer_public_key TEXT NOT NULL CHECK (signer_public_key <> ''),
                signature TEXT NOT NULL CHECK (signature <> '')
            );

            CREATE TRIGGER IF NOT EXISTS authority_budget_anchor_commits_immutable
            BEFORE UPDATE ON authority_budget_anchor_commits
            BEGIN
                SELECT RAISE(ABORT, 'budget anchor commitment is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS authority_budget_anchor_commits_no_delete
            BEFORE DELETE ON authority_budget_anchor_commits
            BEGIN
                SELECT RAISE(ABORT, 'budget anchor commitment is immutable');
            END;
            "#,
        )?;
        if !Self::table_has_column(&connection, "authority_state", "public_key_hex")? {
            connection.execute(
                "ALTER TABLE authority_state ADD COLUMN public_key_hex TEXT",
                [],
            )?;
        }
        if !Self::table_has_column(
            &connection,
            "authority_cluster_fence",
            "authority_generation",
        )? {
            connection.execute(
                "ALTER TABLE authority_cluster_fence ADD COLUMN authority_generation INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !Self::table_has_column(
            &connection,
            "authority_cluster_fence",
            "authority_rotated_at",
        )? {
            connection.execute(
                "ALTER TABLE authority_cluster_fence ADD COLUMN authority_rotated_at INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !Self::table_has_column(&connection, "authority_trusted_keys", "lifecycle_json")? {
            connection.execute(
                "ALTER TABLE authority_trusted_keys ADD COLUMN lifecycle_json TEXT",
                [],
            )?;
        }
        if !Self::table_has_column(&connection, "authority_state", "observed_ms")? {
            connection.execute(
                "ALTER TABLE authority_state ADD COLUMN observed_ms INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        replication::ensure_schema(&connection)?;
        crate::stamp_schema_version(
            &connection,
            AUTHORITY_STORE_SCHEMA_KEY,
            AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| AuthorityStoreError::Schema(error.to_string()))?;
        custody.validate(&connection)?;
        Ok(connection)
    }

    fn read_status_from_connection(
        connection: &Connection,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        let (public_key, generation, rotated_at) =
            Self::read_public_state_from_connection(connection)?;
        Ok(AuthorityStatus {
            issuer_state: replication::read_snapshot(connection)?,
            public_key,
            generation,
            rotated_at,
            trusted_public_keys: Self::read_trusted_public_keys(connection)?,
        })
    }

    fn read_keypair_from_connection(
        connection: &Connection,
    ) -> Result<Keypair, AuthorityStoreError> {
        let seed_hex = connection.query_row(
            r#"
            SELECT seed_hex
            FROM authority_state
            WHERE singleton_id = 1
            "#,
            [],
            |row| row.get::<_, String>(0),
        )?;
        Keypair::from_seed_hex(seed_hex.trim()).map_err(Into::into)
    }

    fn read_budget_anchor_commit_chain(
        connection: &Connection,
    ) -> Result<Vec<SignedBudgetSnapshotAnchorCommitment>, AuthorityStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT commit_sequence, previous_chain_digest, chain_digest,
                   anchor_set_digest, leader_url, election_term, committed_at,
                   signer_public_key, signature
            FROM authority_budget_anchor_commits
            ORDER BY commit_sequence
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;
        rows.map(|row| {
            let (sequence, previous, chain, anchors, leader, term, at, signer, signature) = row?;
            Ok(SignedBudgetSnapshotAnchorCommitment {
                body: BudgetSnapshotAnchorCommitment {
                    schema: "chio.budget-snapshot-anchor-commitment.v1".to_string(),
                    commit_sequence: authority_unsigned(sequence, "anchor sequence")?,
                    previous_chain_digest: previous,
                    chain_digest: chain,
                    anchor_set_digest: anchors,
                    leader_url: leader,
                    election_term: authority_unsigned(term, "anchor election term")?,
                    committed_at: authority_unsigned(at, "anchor commit time")?,
                    signer_public_key: signer,
                },
                signature: Signature::from_hex(&signature)?,
            })
        })
        .collect()
    }

    fn read_public_state_from_connection(
        connection: &Connection,
    ) -> Result<(PublicKey, u64, u64), AuthorityStoreError> {
        let (seed_hex, public_key_hex, generation, rotated_at) = connection.query_row(
            r#"
            SELECT seed_hex, public_key_hex, generation, rotated_at
            FROM authority_state
            WHERE singleton_id = 1
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        let public_key = match public_key_hex
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(public_key_hex) => PublicKey::from_hex(public_key_hex)?,
            None => Keypair::from_seed_hex(seed_hex.trim())?.public_key(),
        };
        Ok((
            public_key,
            authority_unsigned(
                authority_generation(authority_unsigned(generation, "generation")?)?,
                "generation",
            )?,
            authority_unsigned(rotated_at, "rotation time")?,
        ))
    }

    fn read_current_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        let mut connection = Self::open_connection(&self.custody)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        lifecycle::observe_time(&transaction, self.clock.unix_millis()?)?;
        chio_kernel::authority::replication::validate_state(&replication::read_snapshot(
            &transaction,
        )?)?;
        let keypair = Self::read_keypair_from_connection(&transaction)?;
        let status = Self::read_status_from_connection(&transaction)?;
        if keypair.public_key() != status.public_key {
            return Err(AuthorityStoreError::Fence(format!(
                "local signing seed public key {} does not match replicated authority public key {}",
                keypair.public_key().to_hex(),
                status.public_key.to_hex(),
            )));
        }
        transaction.commit()?;
        self.update_cached_public_key(status.public_key);
        Ok(keypair)
    }

    fn table_has_column(
        connection: &Connection,
        table: &str,
        column: &str,
    ) -> Result<bool, AuthorityStoreError> {
        let pragma = format!("PRAGMA table_info({table})");
        let mut statement = connection.prepare(&pragma)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            if row.get::<_, String>(1)? == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn update_cached_public_key(&self, public_key: PublicKey) {
        match self.cached_public_key.lock() {
            Ok(mut guard) => *guard = public_key,
            Err(poisoned) => {
                tracing::error!(
                    "cached_public_key mutex is poisoned - recovering possibly-stale key material"
                );
                *poisoned.into_inner() = public_key;
            }
        }
    }

    fn cached_public_key(&self) -> PublicKey {
        match self.cached_public_key.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                tracing::error!(
                    "cached_public_key mutex is poisoned - reading possibly-stale key material"
                );
                poisoned.into_inner().clone()
            }
        }
    }

    fn read_trusted_public_keys(
        connection: &Connection,
    ) -> Result<Vec<PublicKey>, AuthorityStoreError> {
        Self::read_trusted_key_snapshots(connection)?
            .into_iter()
            .map(|key| PublicKey::from_hex(&key.public_key_hex).map_err(AuthorityStoreError::from))
            .collect()
    }

    fn read_trusted_key_snapshots(
        connection: &Connection,
    ) -> Result<Vec<AuthorityTrustedKeySnapshot>, AuthorityStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT public_key_hex, generation, activated_at, lifecycle_json
            FROM authority_trusted_keys
            ORDER BY generation ASC, activated_at ASC, public_key_hex ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (key, generation, at, lifecycle) = row?;
            Ok(AuthorityTrustedKeySnapshot {
                public_key_hex: PublicKey::from_hex(key.trim())?.to_hex(),
                generation: authority_unsigned(
                    authority_generation(authority_unsigned(
                        generation,
                        "trusted-key generation",
                    )?)?,
                    "trusted-key generation",
                )?,
                activated_at: authority_unsigned(at, "trusted-key activation time")?,
                lifecycle: lifecycle
                    .as_deref()
                    .map(replication::decode_lifecycle)
                    .transpose()?,
            })
        })
        .collect()
    }

    fn read_cluster_fence_from_connection(
        connection: &Connection,
    ) -> Result<AuthorityClusterFence, AuthorityStoreError> {
        let (leader_url, election_term, updated_at, authority_generation, authority_rotated_at) =
            connection.query_row(
                r#"
            SELECT leader_url, election_term, updated_at, authority_generation, authority_rotated_at
            FROM authority_cluster_fence
            WHERE singleton_id = 1
            "#,
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )?;
        Ok(AuthorityClusterFence {
            leader_url,
            election_term: authority_unsigned(election_term, "election term")?,
            updated_at: authority_unsigned(updated_at, "fence update time")?,
            authority_generation: authority_unsigned(authority_generation, "fence generation")?,
            authority_rotated_at: authority_unsigned(authority_rotated_at, "fence rotation time")?,
        })
    }

    fn write_cluster_fence_to_connection(
        connection: &Connection,
        leader_url: Option<String>,
        election_term: u64,
        now: u64,
    ) -> Result<(), AuthorityStoreError> {
        let (_, authority_generation, authority_rotated_at) =
            Self::read_public_state_from_connection(connection)?;
        connection.execute(
            r#"
            UPDATE authority_cluster_fence
            SET
                leader_url = ?1,
                election_term = ?2,
                updated_at = ?3,
                authority_generation = ?4,
                authority_rotated_at = ?5
            WHERE singleton_id = 1
            "#,
            params![
                leader_url,
                authority_sqlite_integer(election_term, "election term")?,
                authority_sqlite_integer(now, "fence update time")?,
                authority_sqlite_integer(authority_generation, "fence generation")?,
                authority_sqlite_integer(authority_rotated_at, "fence rotation time")?,
            ],
        )?;
        Ok(())
    }
}

impl CapabilityAuthority for SqliteCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.status()
            .map(|status| status.public_key)
            .unwrap_or_else(|_| self.cached_public_key())
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.status()
            .map(|status| status.trusted_public_keys)
            .unwrap_or_default()
    }

    fn check_issuer_lifecycle(
        &self,
        issuer: &PublicKey,
        issued_at: u64,
        now: u64,
    ) -> Result<(), KernelError> {
        self.check_managed_issuer(issuer, issued_at, now)
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        ensure_capability_issuance_supported(&scope)?;
        let issue = || -> Result<CapabilityToken, AuthorityStoreError> {
            let mut connection = Self::open_connection(&self.custody)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let observed = self.clock.unix_millis()?;
            lifecycle::observe_time(&transaction, observed)?;
            let keypair = Self::read_keypair_from_connection(&transaction)?;
            let snapshot = replication::read_snapshot(&transaction)?;
            chio_kernel::authority::replication::validate_state(&snapshot)?;
            if keypair.public_key().to_hex() != snapshot.public_key_hex {
                return Err(AuthorityStoreError::Fence(
                    "issuance requires custody of the current head".into(),
                ));
            }
            let now = observed.as_secs();
            let body = CapabilityTokenBody {
                id: format!("cap-{}", Uuid::now_v7()),
                issuer: keypair.public_key(),
                subject: subject.clone(),
                scope,
                issued_at: now,
                expires_at: now.checked_add(ttl_seconds).ok_or_else(|| {
                    AuthorityStoreError::Fence(
                        "capability expiry overflows the timestamp domain".into(),
                    )
                })?,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            };

            let capability = CapabilityToken::sign(body, &keypair)?;
            transaction.commit()?;
            Ok(capability)
        };
        issue().map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use chio_core::capability::scope::{Operation, ToolGrant};
    use chio_kernel::LocalCapabilityAuthority;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("{prefix}-{nonce}"))
            .join("authority.sqlite3")
    }

    #[test]
    fn local_capability_authority_signs_capabilities() {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let subject = Keypair::generate().public_key();
        let capability = authority
            .issue_capability(
                &subject,
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap();

        assert_eq!(capability.subject, subject);
        assert_eq!(capability.issuer, authority.authority_public_key());
        assert!(capability.id.starts_with("cap-"));
        assert!(capability.verify_signature().unwrap());
    }

    #[test]
    fn sqlite_capability_authority_persists_and_rotates_across_handles() {
        let path = unique_db_path("chio-authority");
        let authority_a = SqliteCapabilityAuthority::open(&path).unwrap();
        let authority_b = SqliteCapabilityAuthority::open(&path).unwrap();

        let before = authority_a.status().unwrap();
        assert_eq!(before.generation, 1);
        assert_eq!(authority_b.status().unwrap().public_key, before.public_key);

        let rotated = authority_a.rotate().unwrap();
        assert_eq!(rotated.generation, 2);
        assert_ne!(rotated.public_key, before.public_key);

        let observed = authority_b.status().unwrap();
        assert_eq!(observed.public_key, rotated.public_key);
        assert_eq!(observed.generation, rotated.generation);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_issues_with_current_rotated_key() {
        let path = unique_db_path("chio-authority-issue");
        let authority = SqliteCapabilityAuthority::open(&path).unwrap();
        let subject = Keypair::generate().public_key();
        let first = authority
            .issue_capability(
                &subject,
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap();
        let rotated = authority.rotate().unwrap();
        let second = authority
            .issue_capability(
                &subject,
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap();

        assert_ne!(first.issuer, second.issuer);
        assert_eq!(second.issuer, rotated.public_key);
        assert!(second.verify_signature().unwrap());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_snapshot_updates_public_view_without_copying_seed() {
        let source_path = unique_db_path("chio-authority-source");
        let follower_path = unique_db_path("chio-authority-follower");
        let source = SqliteCapabilityAuthority::open(&source_path).unwrap();
        let follower = SqliteCapabilityAuthority::open(&follower_path).unwrap();

        let follower_local_key = follower.current_keypair().unwrap().public_key();
        let anchor = source.initialize_replication("test-custody").unwrap();
        follower.pin_replication_anchor(&anchor).unwrap();
        let rotated = source.rotate().unwrap();
        let snapshot = source.signed_snapshot().unwrap();

        assert!(follower.apply_signed_snapshot(&snapshot).unwrap());

        let follower_status = follower.status().unwrap();
        assert_eq!(follower_status.public_key, rotated.public_key);
        assert_eq!(follower_status.generation, rotated.generation);
        let error = match follower.current_keypair() {
            Ok(_) => panic!("mismatched follower keypair should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("does not match replicated authority public key"));
        assert!(error.contains(&follower_local_key.to_hex()));

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(follower_path);
    }

    #[test]
    fn sqlite_capability_authority_same_term_snapshot_does_not_clear_fenced_leader() {
        let path = unique_db_path("chio-authority-fence");
        let authority = SqliteCapabilityAuthority::open(&path).unwrap();

        assert!(authority
            .seed_cluster_fence(Some("http://leader-a"), 7)
            .unwrap());
        assert!(!authority.seed_cluster_fence(None, 7).unwrap());

        let fence = authority.cluster_fence().unwrap();
        let status = authority.status().unwrap();
        assert_eq!(fence.election_term, 7);
        assert_eq!(fence.leader_url.as_deref(), Some("http://leader-a"));
        assert_eq!(fence.authority_generation, status.generation);
        assert_eq!(fence.authority_rotated_at, status.rotated_at);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_enforce_cluster_fence_rejects_stale_rotation() {
        let path = unique_db_path("chio-authority-fence-stale-rotation");
        let authority = SqliteCapabilityAuthority::open(&path).unwrap();

        assert!(authority
            .seed_cluster_fence(Some("http://leader-a"), 7)
            .unwrap());
        let fence = authority.cluster_fence().unwrap();
        authority.rotate().unwrap();

        let error = authority
            .enforce_cluster_fence("http://leader-a", 7)
            .expect_err("stale persisted fence should fail closed")
            .to_string();
        assert!(error.contains("persisted authority fence generation"));
        assert!(error.contains(&fence.authority_generation.to_string()));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_seed_cluster_fence_refreshes_same_term_authority_state() {
        let path = unique_db_path("chio-authority-fence-same-term-refresh");
        let authority = SqliteCapabilityAuthority::open(&path).unwrap();

        assert!(authority
            .seed_cluster_fence(Some("http://leader-a"), 7)
            .unwrap());
        authority.rotate().unwrap();

        assert!(authority
            .seed_cluster_fence(Some("http://leader-a"), 7)
            .unwrap());
        authority
            .enforce_cluster_fence("http://leader-a", 7)
            .expect("same-term reseed should refresh authority generation");

        let fence = authority.cluster_fence().unwrap();
        let status = authority.status().unwrap();
        assert_eq!(fence.election_term, 7);
        assert_eq!(fence.leader_url.as_deref(), Some("http://leader-a"));
        assert_eq!(fence.authority_generation, status.generation);
        assert_eq!(fence.authority_rotated_at, status.rotated_at);

        let _ = fs::remove_file(path);
    }
}
