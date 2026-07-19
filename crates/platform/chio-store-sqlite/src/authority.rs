use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_kernel::{
    AuthoritySnapshot, AuthorityStatus, AuthorityStoreError, AuthorityTrustedKeySnapshot,
    CapabilityAuthority, KernelError,
};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use uuid::Uuid;

pub struct SqliteCapabilityAuthority {
    path: PathBuf,
    open_mode: AuthorityOpenMode,
    cached_public_key: Mutex<PublicKey>,
    cached_trusted_public_keys: Mutex<Vec<PublicKey>>,
}

#[derive(Clone, Copy)]
enum AuthorityOpenMode {
    CreateOrMigrate,
    ExistingOnly,
}

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
        Self::open_with_mode(path, AuthorityOpenMode::CreateOrMigrate)
    }

    /// Open an initialized authority database without creating or repairing it.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, AuthorityStoreError> {
        Self::open_with_mode(path, AuthorityOpenMode::ExistingOnly)
    }

    fn open_with_mode(
        path: impl AsRef<Path>,
        open_mode: AuthorityOpenMode,
    ) -> Result<Self, AuthorityStoreError> {
        let path = path.as_ref().to_path_buf();
        if matches!(open_mode, AuthorityOpenMode::CreateOrMigrate) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        }

        let connection = Self::open_connection(&path, open_mode)?;
        let status = match open_mode {
            AuthorityOpenMode::CreateOrMigrate => {
                Self::bootstrap_authority_state(&connection)?;
                Self::read_status_from_connection(&connection)?
            }
            AuthorityOpenMode::ExistingOnly => {
                Self::validate_existing_authority_state(&connection)?
            }
        };
        Ok(Self {
            path,
            open_mode,
            cached_public_key: Mutex::new(status.public_key),
            cached_trusted_public_keys: Mutex::new(status.trusted_public_keys),
        })
    }

    fn bootstrap_authority_state(connection: &Connection) -> Result<(), AuthorityStoreError> {
        let bootstrap = Keypair::generate();
        connection.execute(
            r#"
            INSERT INTO authority_state (singleton_id, seed_hex, public_key_hex, generation, rotated_at)
            VALUES (1, ?1, ?2, 1, ?3)
            ON CONFLICT(singleton_id) DO NOTHING
            "#,
            params![
                bootstrap.seed_hex(),
                bootstrap.public_key().to_hex(),
                unix_now() as i64
            ],
        )?;
        let current_public_key = connection
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
        connection.execute(
            r#"
            UPDATE authority_state
            SET public_key_hex = COALESCE(NULLIF(public_key_hex, ''), ?1)
            WHERE singleton_id = 1
            "#,
            params![current_public_key.public_key().to_hex()],
        )?;
        connection.execute(
            r#"
            INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at)
            VALUES (?1, 1, ?2)
            ON CONFLICT(public_key_hex) DO NOTHING
            "#,
            params![current_public_key.public_key().to_hex(), unix_now() as i64],
        )?;
        Ok(())
    }

    pub fn status(&self) -> Result<AuthorityStatus, AuthorityStoreError> {
        let connection = self.connection()?;
        let status = Self::read_status_from_connection(&connection)?;
        self.update_cached_public_key(status.public_key.clone());
        self.update_cached_trusted_public_keys(status.trusted_public_keys.clone());
        Ok(status)
    }

    pub fn rotate(&self) -> Result<AuthorityStatus, AuthorityStoreError> {
        self.rotate_with_hook(|| {})
    }

    fn rotate_with_hook(
        &self,
        after_state_update: impl FnOnce(),
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status_before = Self::read_status_from_connection(&transaction)?;
        let keypair = Keypair::generate();
        let rotated_at = unix_now();
        let next_generation = status_before.generation.checked_add(1).ok_or_else(|| {
            AuthorityStoreError::Fence(
                "authority generation overflowed during rotation".to_string(),
            )
        })?;
        let stored_generation = i64::try_from(status_before.generation).map_err(|_| {
            AuthorityStoreError::Fence(
                "authority generation exceeds the SQLite integer range".to_string(),
            )
        })?;
        let next_generation_i64 = i64::try_from(next_generation).map_err(|_| {
            AuthorityStoreError::Fence(
                "next authority generation exceeds the SQLite integer range".to_string(),
            )
        })?;
        let rotated_at_i64 = i64::try_from(rotated_at).map_err(|_| {
            AuthorityStoreError::Fence(
                "authority rotation time exceeds the SQLite integer range".to_string(),
            )
        })?;

        let updated = transaction.execute(
            r#"
            UPDATE authority_state
            SET seed_hex = ?1, public_key_hex = ?2, generation = ?3, rotated_at = ?4
            WHERE singleton_id = 1 AND generation = ?5
            "#,
            params![
                keypair.seed_hex(),
                keypair.public_key().to_hex(),
                next_generation_i64,
                rotated_at_i64,
                stored_generation,
            ],
        )?;
        if updated != 1 {
            return Err(AuthorityStoreError::Fence(
                "authority generation changed during rotation".to_string(),
            ));
        }
        after_state_update();
        transaction.execute(
            r#"
            INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(public_key_hex) DO NOTHING
            "#,
            params![
                keypair.public_key().to_hex(),
                next_generation_i64,
                rotated_at_i64,
            ],
        )?;
        let fence = Self::read_cluster_fence_from_connection(&transaction)?;
        Self::write_cluster_fence_to_connection(
            &transaction,
            fence.leader_url,
            fence.election_term,
        )?;

        let status = Self::read_status_from_connection(&transaction)?;
        transaction.commit()?;
        self.update_cached_public_key(status.public_key.clone());
        self.update_cached_trusted_public_keys(status.trusted_public_keys.clone());
        Ok(status)
    }

    /// Run one signing action while holding the same durable SQLite write
    /// exclusion domain used by authority rotation. The exact public key and
    /// generation are checked after the lock is acquired, and the action
    /// completes before the transaction releases rotation.
    pub fn with_locked_current_keypair<T>(
        &self,
        expected_public_key: &PublicKey,
        expected_generation: u64,
        cluster_fence: Option<(&str, u64)>,
        action: impl FnOnce(&Keypair, &AuthorityStatus) -> T,
    ) -> Result<T, AuthorityStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((leader_url, election_term)) = cluster_fence {
            Self::enforce_cluster_fence_on_connection(&transaction, leader_url, election_term)?;
        }
        let status = Self::read_status_from_connection(&transaction)?;
        let keypair = Self::read_keypair_from_connection(&transaction)?;
        if &status.public_key != expected_public_key
            || status.generation != expected_generation
            || keypair.public_key() != status.public_key
        {
            return Err(AuthorityStoreError::Fence(
                "authority signing request does not match the locked current epoch".to_string(),
            ));
        }
        let result = action(&keypair, &status);
        transaction.commit()?;
        self.update_cached_public_key(status.public_key.clone());
        self.update_cached_trusted_public_keys(status.trusted_public_keys.clone());
        Ok(result)
    }

    pub fn snapshot(&self) -> Result<AuthoritySnapshot, AuthorityStoreError> {
        let connection = self.connection()?;
        let status = Self::read_status_from_connection(&connection)?;
        Ok(AuthoritySnapshot {
            public_key_hex: status.public_key.to_hex(),
            generation: status.generation,
            rotated_at: status.rotated_at,
            trusted_keys: Self::read_trusted_key_snapshots(&connection)?,
        })
    }

    /// Validate the public-key shape of an observational peer snapshot.
    /// This method never mutates signing custody or verifier trust.
    pub fn apply_snapshot(
        &self,
        snapshot: &AuthoritySnapshot,
    ) -> Result<bool, AuthorityStoreError> {
        PublicKey::from_hex(snapshot.public_key_hex.trim())?;
        for trusted_key in &snapshot.trusted_keys {
            PublicKey::from_hex(trusted_key.public_key_hex.trim())?;
        }
        // Peer snapshots are unauthenticated by the capability authority. They
        // are observational cluster metadata only and cannot mutate either
        // signing custody or verification trust. Witnessed key-log replay is
        // the sole trust-extension path.
        Ok(false)
    }

    pub fn current_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        self.read_current_keypair()
    }

    pub fn local_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        let connection = self.connection()?;
        Self::read_keypair_from_connection(&connection)
    }

    pub fn cluster_fence(&self) -> Result<AuthorityClusterFence, AuthorityStoreError> {
        let connection = self.connection()?;
        Self::read_cluster_fence_from_connection(&connection)
    }

    pub fn seed_cluster_fence(
        &self,
        leader_url: Option<&str>,
        election_term: u64,
    ) -> Result<bool, AuthorityStoreError> {
        let mut connection = self.connection()?;
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
            Self::write_cluster_fence_to_connection(&transaction, next_leader, election_term)?;
        }
        transaction.commit()?;
        Ok(should_update)
    }

    pub fn enforce_cluster_fence(
        &self,
        leader_url: &str,
        election_term: u64,
    ) -> Result<(), AuthorityStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::enforce_cluster_fence_on_connection(&transaction, leader_url, election_term)?;
        transaction.commit()?;
        Ok(())
    }

    fn enforce_cluster_fence_on_connection(
        connection: &Connection,
        leader_url: &str,
        election_term: u64,
    ) -> Result<(), AuthorityStoreError> {
        let current = Self::read_cluster_fence_from_connection(connection)?;
        let (_, authority_generation, authority_rotated_at) =
            Self::read_public_state_from_connection(connection)?;
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
            connection,
            Some(leader_url.to_string()),
            election_term,
        )?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path, self.open_mode)?;
        if matches!(self.open_mode, AuthorityOpenMode::ExistingOnly) {
            Self::validate_existing_authority_state(&connection)?;
        }
        Ok(connection)
    }

    fn open_connection(
        path: &Path,
        open_mode: AuthorityOpenMode,
    ) -> Result<Connection, AuthorityStoreError> {
        let connection = match open_mode {
            AuthorityOpenMode::CreateOrMigrate => Connection::open(path)?,
            AuthorityOpenMode::ExistingOnly => Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?,
        };
        if matches!(open_mode, AuthorityOpenMode::ExistingOnly) {
            connection.execute_batch(
                r#"
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;
                "#,
            )?;
            return Ok(connection);
        }
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
                activated_at INTEGER NOT NULL
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
        Ok(connection)
    }

    fn validate_existing_authority_state(
        connection: &Connection,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
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
        let local_keypair = Keypair::from_seed_hex(seed_hex.trim())?;
        let public_key_hex = public_key_hex
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AuthorityStoreError::Fence("existing authority state has no public key".to_string())
            })?;
        let public_key = PublicKey::from_hex(public_key_hex)?;
        if local_keypair.public_key() != public_key {
            return Err(AuthorityStoreError::Fence(
                "existing authority signing seed does not match its current public key".to_string(),
            ));
        }
        if generation < 1 || rotated_at < 0 {
            return Err(AuthorityStoreError::Fence(
                "existing authority state has an invalid generation or rotation time".to_string(),
            ));
        }

        let status = Self::read_status_from_connection(connection)?;
        if status.public_key != public_key
            || !status.trusted_public_keys.contains(&status.public_key)
        {
            return Err(AuthorityStoreError::Fence(
                "existing authority state does not trust its current public key".to_string(),
            ));
        }
        Self::read_cluster_fence_from_connection(connection)?;
        Ok(status)
    }

    fn read_status_from_connection(
        connection: &Connection,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        let (public_key, generation, rotated_at) =
            Self::read_public_state_from_connection(connection)?;
        Ok(AuthorityStatus {
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
            generation.max(0) as u64,
            rotated_at.max(0) as u64,
        ))
    }

    fn read_current_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        let connection = self.connection()?;
        let keypair = Self::read_keypair_from_connection(&connection)?;
        let status = Self::read_status_from_connection(&connection)?;
        self.update_cached_public_key(status.public_key.clone());
        self.update_cached_trusted_public_keys(status.trusted_public_keys.clone());
        if keypair.public_key() != status.public_key {
            return Err(AuthorityStoreError::Fence(format!(
                "local signing seed public key {} does not match replicated authority public key {}",
                keypair.public_key().to_hex(),
                status.public_key.to_hex(),
            )));
        }
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

    fn update_cached_trusted_public_keys(&self, public_keys: Vec<PublicKey>) {
        match self.cached_trusted_public_keys.lock() {
            Ok(mut guard) => *guard = public_keys,
            Err(poisoned) => {
                tracing::error!(
                    "cached_trusted_public_keys mutex is poisoned - recovering possibly-stale key material"
                );
                *poisoned.into_inner() = public_keys;
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

    fn cached_trusted_public_keys(&self) -> Vec<PublicKey> {
        match self.cached_trusted_public_keys.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                tracing::error!(
                    "cached_trusted_public_keys mutex is poisoned - reading possibly-stale key material"
                );
                poisoned.into_inner().clone()
            }
        }
    }

    fn read_trusted_public_keys(
        connection: &Connection,
    ) -> Result<Vec<PublicKey>, AuthorityStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT public_key_hex
            FROM authority_trusted_keys
            ORDER BY generation ASC, activated_at ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let public_key_hex = row?;
            PublicKey::from_hex(public_key_hex.trim()).map_err(AuthorityStoreError::from)
        })
        .collect()
    }

    fn read_trusted_key_snapshots(
        connection: &Connection,
    ) -> Result<Vec<AuthorityTrustedKeySnapshot>, AuthorityStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT public_key_hex, generation, activated_at
            FROM authority_trusted_keys
            ORDER BY generation ASC, activated_at ASC, public_key_hex ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AuthorityTrustedKeySnapshot {
                public_key_hex: row.get(0)?,
                generation: row.get::<_, i64>(1)?.max(0) as u64,
                activated_at: row.get::<_, i64>(2)?.max(0) as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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
            election_term: election_term.max(0) as u64,
            updated_at: updated_at.max(0) as u64,
            authority_generation: authority_generation.max(0) as u64,
            authority_rotated_at: authority_rotated_at.max(0) as u64,
        })
    }

    fn write_cluster_fence_to_connection(
        connection: &Connection,
        leader_url: Option<String>,
        election_term: u64,
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
                election_term as i64,
                unix_now() as i64,
                authority_generation as i64,
                authority_rotated_at as i64,
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
            .unwrap_or_else(|_| self.cached_trusted_public_keys())
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let keypair = self
            .read_current_keypair()
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        let now = unix_now();
        let body = CapabilityTokenBody {
            id: format!("cap-{}", Uuid::now_v7()),
            issuer: keypair.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };

        CapabilityToken::sign(body, &keypair)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use chio_core::capability::scope::{Operation, ToolGrant};
    use chio_kernel::LocalCapabilityAuthority;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
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
    fn concurrent_rotations_serialize_unique_generations() {
        let path = unique_db_path("chio-authority-concurrent-rotation");
        let initial = SqliteCapabilityAuthority::open(&path)
            .unwrap()
            .status()
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                let authority = SqliteCapabilityAuthority::open_existing(path).unwrap();
                barrier.wait();
                authority.rotate().unwrap()
            }));
        }
        barrier.wait();
        let mut generations = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().generation)
            .collect::<Vec<_>>();
        generations.sort_unstable();

        assert_eq!(
            generations,
            vec![initial.generation + 1, initial.generation + 2]
        );
        let final_status = SqliteCapabilityAuthority::open_existing(&path)
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(final_status.generation, initial.generation + 2);
        assert_eq!(final_status.trusted_public_keys.len(), 3);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn authority_observer_never_sees_new_current_key_without_trust_row() {
        let path = unique_db_path("chio-authority-atomic-observer");
        let initial = SqliteCapabilityAuthority::open(&path)
            .unwrap()
            .status()
            .unwrap();
        let (updated_tx, updated_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            SqliteCapabilityAuthority::open_existing(writer_path)
                .unwrap()
                .rotate_with_hook(|| {
                    updated_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap()
        });

        updated_rx.recv().unwrap();
        let observed_while_uncommitted = SqliteCapabilityAuthority::open_existing(&path)
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(observed_while_uncommitted, initial);
        assert!(observed_while_uncommitted
            .trusted_public_keys
            .contains(&observed_while_uncommitted.public_key));

        release_tx.send(()).unwrap();
        let rotated = writer.join().unwrap();
        assert!(rotated.trusted_public_keys.contains(&rotated.public_key));
        assert_eq!(rotated.generation, initial.generation + 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn locked_signing_epoch_excludes_rotation_until_signature_is_complete() {
        let path = unique_db_path("chio-authority-sign-rotation");
        let initial = SqliteCapabilityAuthority::open(&path)
            .unwrap()
            .status()
            .unwrap();
        let message = b"authority signing exclusion".to_vec();
        let (locked_tx, locked_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let signing_path = path.clone();
        let expected_public_key = initial.public_key.clone();
        let expected_generation = initial.generation;
        let signing_message = message.clone();
        let signer = thread::spawn(move || {
            SqliteCapabilityAuthority::open_existing(signing_path)
                .unwrap()
                .with_locked_current_keypair(
                    &expected_public_key,
                    expected_generation,
                    None,
                    |keypair, status| {
                        locked_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        (status.clone(), keypair.sign(&signing_message))
                    },
                )
                .unwrap()
        });

        locked_rx.recv().unwrap();
        let rotation_path = path.clone();
        let (rotated_tx, rotated_rx) = mpsc::sync_channel(1);
        let rotator = thread::spawn(move || {
            let rotated = SqliteCapabilityAuthority::open_existing(rotation_path)
                .unwrap()
                .rotate()
                .unwrap();
            rotated_tx.send(rotated.clone()).unwrap();
            rotated
        });
        assert!(rotated_rx.recv_timeout(Duration::from_millis(100)).is_err());

        release_tx.send(()).unwrap();
        let (signed_epoch, signature) = signer.join().unwrap();
        let rotated = rotator.join().unwrap();
        assert_eq!(signed_epoch, initial);
        assert!(initial.public_key.verify(&message, &signature));
        assert_eq!(rotated.generation, initial.generation + 1);
        assert_ne!(rotated.public_key, initial.public_key);

        let stale = SqliteCapabilityAuthority::open_existing(&path)
            .unwrap()
            .with_locked_current_keypair(&initial.public_key, initial.generation, None, |_, _| ());
        assert!(stale.is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_open_existing_loads_initialized_state() {
        let path = unique_db_path("chio-authority-open-existing");
        let created = SqliteCapabilityAuthority::open(&path).unwrap();
        let expected = created.status().unwrap();

        let existing = SqliteCapabilityAuthority::open_existing(&path).unwrap();
        assert_eq!(existing.status().unwrap(), expected);
        assert_eq!(existing.authority_public_key(), expected.public_key);
        assert_eq!(existing.trusted_public_keys(), expected.trusted_public_keys);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_open_existing_missing_path_creates_nothing() {
        let missing_file = unique_db_path("chio-authority-missing-file");
        assert!(!missing_file.exists());
        assert!(SqliteCapabilityAuthority::open_existing(&missing_file).is_err());
        assert!(!missing_file.exists());

        let root = unique_db_path("chio-authority-missing-parent");
        let path = root.join("nested").join("authority.sqlite3");
        assert!(!root.exists());

        assert!(SqliteCapabilityAuthority::open_existing(&path).is_err());
        assert!(!root.exists());
        assert!(!path.exists());
    }

    #[test]
    fn sqlite_capability_authority_existing_handle_never_recreates_removed_file() {
        let path = unique_db_path("chio-authority-existing-handle");
        drop(SqliteCapabilityAuthority::open(&path).unwrap());
        let existing = SqliteCapabilityAuthority::open_existing(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert!(existing.status().is_err());
        assert!(!path.exists());
    }

    #[test]
    fn sqlite_capability_authority_open_existing_rejects_empty_schema_without_repair() {
        let path = unique_db_path("chio-authority-empty-schema");
        drop(Connection::open(&path).unwrap());

        assert!(SqliteCapabilityAuthority::open_existing(&path).is_err());
        let connection = Connection::open(&path).unwrap();
        let table_count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'authority_%'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(table_count, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_open_existing_rejects_missing_state_without_bootstrap() {
        let path = unique_db_path("chio-authority-missing-state");
        drop(SqliteCapabilityAuthority::open(&path).unwrap());
        let connection = Connection::open(&path).unwrap();
        connection
            .execute("DELETE FROM authority_state WHERE singleton_id = 1", [])
            .unwrap();
        drop(connection);

        assert!(SqliteCapabilityAuthority::open_existing(&path).is_err());
        let connection = Connection::open(&path).unwrap();
        let state_count = connection
            .query_row("SELECT COUNT(*) FROM authority_state", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(state_count, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_open_existing_rejects_seed_public_key_mismatch() {
        let path = unique_db_path("chio-authority-seed-key-mismatch");
        drop(SqliteCapabilityAuthority::open(&path).unwrap());
        let forged_public_key = Keypair::generate().public_key();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE authority_state SET public_key_hex = ?1 WHERE singleton_id = 1",
                params![forged_public_key.to_hex()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at) VALUES (?1, 1, 1)",
                params![forged_public_key.to_hex()],
            )
            .unwrap();
        drop(connection);

        assert!(SqliteCapabilityAuthority::open_existing(&path).is_err());
        let connection = Connection::open(&path).unwrap();
        let stored_public_key = connection
            .query_row(
                "SELECT public_key_hex FROM authority_state WHERE singleton_id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(stored_public_key, forged_public_key.to_hex());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_existing_reads_never_repair_tampered_state() {
        let path = unique_db_path("chio-authority-existing-no-repair");
        drop(SqliteCapabilityAuthority::open(&path).unwrap());
        let existing = SqliteCapabilityAuthority::open_existing(&path).unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE authority_state SET public_key_hex = '' WHERE singleton_id = 1",
                [],
            )
            .unwrap();
        drop(connection);

        assert!(existing.status().is_err());
        assert!(existing.current_keypair().is_err());
        let connection = Connection::open(&path).unwrap();
        let stored_public_key = connection
            .query_row(
                "SELECT public_key_hex FROM authority_state WHERE singleton_id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert!(stored_public_key.is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_open_existing_rejects_corrupt_database() {
        let path = unique_db_path("chio-authority-corrupt");
        let corrupt = b"not a sqlite authority database";
        fs::write(&path, corrupt).unwrap();

        assert!(SqliteCapabilityAuthority::open_existing(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), corrupt);

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
    fn sqlite_capability_authority_snapshot_is_observational_without_changing_custody_or_trust() {
        let source_path = unique_db_path("chio-authority-source");
        let follower_path = unique_db_path("chio-authority-follower");
        let source = SqliteCapabilityAuthority::open(&source_path).unwrap();
        let follower = SqliteCapabilityAuthority::open(&follower_path).unwrap();

        let follower_local_key = follower.current_keypair().unwrap().public_key();
        let rotated = source.rotate().unwrap();
        let snapshot = source.snapshot().unwrap();

        assert!(!follower.apply_snapshot(&snapshot).unwrap());

        let follower_status = follower.status().unwrap();
        assert_eq!(follower_status.public_key, follower_local_key);
        assert_ne!(follower_status.public_key, rotated.public_key);
        assert_eq!(
            follower.current_keypair().unwrap().public_key(),
            follower_local_key
        );
        assert!(!follower_status
            .trusted_public_keys
            .iter()
            .any(|key| key == &rotated.public_key));
        assert!(!follower.apply_snapshot(&snapshot).unwrap());

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
