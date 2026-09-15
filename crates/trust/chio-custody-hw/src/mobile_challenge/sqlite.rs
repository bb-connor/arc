use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use super::*;

pub struct SqliteMobileChallengeStore {
    connection: Mutex<Connection>,
    database_custody: Option<DatabaseCustody>,
    max_challenges: usize,
    max_app_attest_counters: usize,
}

struct DatabaseCustody {
    path: PathBuf,
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl DatabaseCustody {
    #[cfg(unix)]
    fn validate(&self) -> Result<(), MobileChallengeError> {
        use std::os::unix::fs::MetadataExt as _;

        validate_database_parent(&self.path)?;
        let path_metadata = std::fs::symlink_metadata(&self.path).map_err(|error| {
            MobileChallengeError::StoreUnavailable(format!(
                "mobile challenge database path metadata failed: {error}"
            ))
        })?;
        let file_metadata = self.file.metadata().map_err(|error| {
            MobileChallengeError::StoreUnavailable(format!(
                "mobile challenge database descriptor metadata failed: {error}"
            ))
        })?;
        validate_database_metadata(&path_metadata)?;
        validate_database_metadata(&file_metadata)?;
        if path_metadata.dev() != self.device
            || path_metadata.ino() != self.inode
            || file_metadata.dev() != self.device
            || file_metadata.ino() != self.inode
        {
            return Err(MobileChallengeError::StoreUnavailable(
                "mobile challenge database file identity changed".to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn validate(&self) -> Result<(), MobileChallengeError> {
        let _ = &self.path;
        Err(MobileChallengeError::StoreUnavailable(
            "mobile challenge database custody requires Unix file identity".to_string(),
        ))
    }
}

impl SqliteMobileChallengeStore {
    pub fn open(path: &Path) -> Result<Self, MobileChallengeError> {
        Self::open_with_limits(
            path,
            DEFAULT_MAX_MOBILE_CHALLENGES,
            DEFAULT_MAX_APP_ATTEST_COUNTERS,
        )
    }

    pub fn open_with_limits(
        path: &Path,
        max_challenges: usize,
        max_app_attest_counters: usize,
    ) -> Result<Self, MobileChallengeError> {
        validate_store_limits(max_challenges, max_app_attest_counters)?;
        validate_database_path(path)?;
        let database_custody = prepare_database_custody(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(path, flags)
            .map_err(|error| unavailable("open mobile challenge database", error))?;
        let store = Self::with_connection(
            connection,
            Some(database_custody),
            max_challenges,
            max_app_attest_counters,
        )?;
        store.validate_database_custody()?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self, MobileChallengeError> {
        let connection = Connection::open_in_memory()
            .map_err(|error| unavailable("open in-memory mobile challenge database", error))?;
        Self::with_connection(
            connection,
            None,
            DEFAULT_MAX_MOBILE_CHALLENGES,
            DEFAULT_MAX_APP_ATTEST_COUNTERS,
        )
    }

    fn with_connection(
        connection: Connection,
        database_custody: Option<DatabaseCustody>,
        max_challenges: usize,
        max_app_attest_counters: usize,
    ) -> Result<Self, MobileChallengeError> {
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| unavailable("configure mobile challenge busy timeout", error))?;
        let store = Self {
            connection: Mutex::new(connection),
            database_custody,
            max_challenges,
            max_app_attest_counters,
        };
        store.execute(|connection| {
            connection
                .execute_batch(
                    "PRAGMA trusted_schema = OFF;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS chio_mobile_attestation_challenges (
                    challenge_id TEXT PRIMARY KEY NOT NULL
                        CHECK (
                            length(challenge_id) = 64
                            AND challenge_id NOT GLOB '*[^0-9a-f]*'
                        ),
                    challenge_json TEXT NOT NULL
                        CHECK (length(challenge_json) BETWEEN 1 AND 4096),
                    expires_at_unix_seconds INTEGER NOT NULL
                        CHECK (expires_at_unix_seconds > 0),
                    consumed_at_unix_seconds INTEGER
                        CHECK (
                            consumed_at_unix_seconds IS NULL
                            OR consumed_at_unix_seconds > 0
                        )
                 ) STRICT, WITHOUT ROWID;
                 CREATE INDEX IF NOT EXISTS idx_chio_mobile_challenge_expiry
                    ON chio_mobile_attestation_challenges (expires_at_unix_seconds);
                 CREATE TABLE IF NOT EXISTS chio_app_attest_counters (
                    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 512),
                    app_id TEXT NOT NULL CHECK (length(app_id) BETWEEN 1 AND 512),
                    counter INTEGER NOT NULL CHECK (counter BETWEEN 0 AND 4294967295),
                    PRIMARY KEY (key_id, app_id)
                 ) STRICT, WITHOUT ROWID;",
                )
                .map_err(|error| unavailable("initialize mobile challenge schema", error))?;
            Ok(())
        })?;
        Ok(store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, MobileChallengeError> {
        self.connection.lock().map_err(|error| {
            MobileChallengeError::StoreUnavailable(format!(
                "mobile challenge database mutex was poisoned: {error}"
            ))
        })
    }

    fn execute<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, MobileChallengeError>,
    ) -> Result<T, MobileChallengeError> {
        self.validate_database_custody()?;
        let (result, connection_validation) = {
            let mut connection = self.lock()?;
            self.validate_connection_binding(&connection)?;
            let result = operation(&mut connection);
            let connection_validation = self.validate_connection_binding(&connection);
            (result, connection_validation)
        };
        let custody_validation = self.validate_database_custody();
        connection_validation?;
        custody_validation?;
        result
    }

    fn validate_database_custody(&self) -> Result<(), MobileChallengeError> {
        match &self.database_custody {
            Some(custody) => custody.validate(),
            None => Ok(()),
        }
    }

    fn validate_connection_binding(
        &self,
        connection: &Connection,
    ) -> Result<(), MobileChallengeError> {
        let Some(custody) = &self.database_custody else {
            return Ok(());
        };
        let actual = chio_sqlite_file_identity::main_database_file_identity(connection).map_err(
            |error| {
                MobileChallengeError::StoreUnavailable(format!(
                    "mobile challenge SQLite descriptor identity failed: {error}"
                ))
            },
        )?;
        #[cfg(unix)]
        if actual.device != custody.device
            || actual.inode != custody.inode
            || actual.link_count != 1
        {
            return Err(MobileChallengeError::StoreUnavailable(
                "mobile challenge SQLite descriptor does not match retained custody".to_string(),
            ));
        }
        #[cfg(not(unix))]
        let _ = (actual, custody);
        Ok(())
    }
}

impl MobileChallengeStore for SqliteMobileChallengeStore {
    fn register_if_absent(
        &self,
        challenge: &IssuedMobileChallenge,
    ) -> Result<bool, MobileChallengeError> {
        challenge.validate()?;
        let challenge_json = canonical_challenge_json(challenge)?;
        let expires_at = sqlite_i64(challenge.expires_at_unix_seconds, "challenge expiry")?;
        self.execute(|connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| unavailable("begin challenge registration", error))?;
            let exists: i64 = transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM chio_mobile_attestation_challenges
                        WHERE challenge_id = ?1
                    )",
                    [challenge.challenge_id.as_str()],
                    |row| row.get(0),
                )
                .map_err(|error| unavailable("query challenge collision", error))?;
            if exists != 0 {
                return Ok(false);
            }
            let retained: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM chio_mobile_attestation_challenges",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| unavailable("count retained challenges", error))?;
            let retained = usize::try_from(retained).map_err(|error| {
                MobileChallengeError::StoreUnavailable(format!(
                    "retained challenge count overflowed: {error}"
                ))
            })?;
            if retained >= self.max_challenges {
                return Err(MobileChallengeError::StoreUnavailable(
                    "mobile challenge capacity was exhausted".to_string(),
                ));
            }
            transaction
                .execute(
                    "INSERT INTO chio_mobile_attestation_challenges (
                        challenge_id, challenge_json, expires_at_unix_seconds,
                        consumed_at_unix_seconds
                     ) VALUES (?1, ?2, ?3, NULL)",
                    params![challenge.challenge_id, challenge_json, expires_at],
                )
                .map_err(|error| unavailable("insert mobile challenge", error))?;
            transaction
                .commit()
                .map_err(|error| unavailable("commit mobile challenge registration", error))?;
            Ok(true)
        })
    }

    fn load_active(
        &self,
        challenge_id: &str,
        now_unix_seconds: u64,
    ) -> Result<MobileChallengeSnapshot, MobileChallengeError> {
        validate_challenge_id(challenge_id)?;
        validate_now(now_unix_seconds)?;
        self.execute(|connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(|error| unavailable("begin challenge read", error))?;
            let (challenge_json, consumed_at): (String, Option<i64>) = transaction
                .query_row(
                    "SELECT challenge_json, consumed_at_unix_seconds
                     FROM chio_mobile_attestation_challenges
                     WHERE challenge_id = ?1",
                    [challenge_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| unavailable("load mobile challenge", error))?
                .ok_or_else(|| MobileChallengeError::Invalid("challenge is unknown".to_string()))?;
            let challenge = decode_challenge_json(&challenge_json)?;
            ensure_sqlite_record_active(&challenge, consumed_at, now_unix_seconds)?;
            let previous_app_attest_counter = match challenge.binding.app_attest_counter_key() {
                Some((key_id, app_id)) => transaction
                    .query_row(
                        "SELECT counter FROM chio_app_attest_counters
                             WHERE key_id = ?1 AND app_id = ?2",
                        params![key_id, app_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(|error| unavailable("load App Attest counter", error))?
                    .map(sqlite_counter)
                    .transpose()?,
                None => None,
            };
            transaction
                .commit()
                .map_err(|error| unavailable("commit mobile challenge read", error))?;
            Ok(MobileChallengeSnapshot {
                challenge,
                previous_app_attest_counter,
            })
        })
    }

    fn consume_verified(
        &self,
        snapshot: &MobileChallengeSnapshot,
        verified_app_attest_counter: Option<u32>,
        now_unix_seconds: u64,
    ) -> Result<(), MobileChallengeError> {
        snapshot.challenge.validate()?;
        validate_now(now_unix_seconds)?;
        let consumed_at = sqlite_i64(now_unix_seconds, "challenge consumption time")?;
        self.execute(|connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| unavailable("begin challenge consumption", error))?;
            let (challenge_json, stored_consumed_at): (String, Option<i64>) = transaction
                .query_row(
                    "SELECT challenge_json, consumed_at_unix_seconds
                     FROM chio_mobile_attestation_challenges
                     WHERE challenge_id = ?1",
                    [snapshot.challenge.challenge_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| unavailable("load challenge for consumption", error))?
                .ok_or_else(|| MobileChallengeError::Invalid("challenge is unknown".to_string()))?;
            let stored = decode_challenge_json(&challenge_json)?;
            if stored != snapshot.challenge {
                return Err(MobileChallengeError::Invalid(
                    "challenge snapshot does not match stored state".to_string(),
                ));
            }
            ensure_sqlite_record_active(&stored, stored_consumed_at, now_unix_seconds)?;
            apply_sqlite_counter_transition(
                &transaction,
                snapshot,
                verified_app_attest_counter,
                self.max_app_attest_counters,
            )?;
            let updated = transaction
                .execute(
                    "UPDATE chio_mobile_attestation_challenges
                     SET consumed_at_unix_seconds = ?2
                     WHERE challenge_id = ?1 AND consumed_at_unix_seconds IS NULL",
                    params![snapshot.challenge.challenge_id, consumed_at],
                )
                .map_err(|error| unavailable("consume mobile challenge", error))?;
            if updated != 1 {
                return Err(MobileChallengeError::Replayed {
                    challenge_id: snapshot.challenge.challenge_id.clone(),
                });
            }
            transaction
                .commit()
                .map_err(|error| unavailable("commit mobile challenge consumption", error))
        })
    }

    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, MobileChallengeError> {
        validate_now(now_unix_seconds)?;
        let now = sqlite_i64(now_unix_seconds, "challenge GC time")?;
        self.execute(|connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| unavailable("begin challenge GC", error))?;
            let removed = transaction
                .execute(
                    "DELETE FROM chio_mobile_attestation_challenges
                     WHERE expires_at_unix_seconds <= ?1",
                    [now],
                )
                .map_err(|error| unavailable("delete expired mobile challenges", error))?;
            transaction
                .commit()
                .map_err(|error| unavailable("commit mobile challenge GC", error))?;
            Ok(removed)
        })
    }
}

fn apply_sqlite_counter_transition(
    transaction: &rusqlite::Transaction<'_>,
    snapshot: &MobileChallengeSnapshot,
    verified_app_attest_counter: Option<u32>,
    max_counters: usize,
) -> Result<(), MobileChallengeError> {
    match snapshot.challenge.binding.app_attest_counter_key() {
        Some((key_id, app_id)) => {
            let counter = verified_app_attest_counter.ok_or_else(|| {
                MobileChallengeError::Invalid(
                    "verified App Attest evidence did not carry a counter".to_string(),
                )
            })?;
            let current = transaction
                .query_row(
                    "SELECT counter FROM chio_app_attest_counters
                     WHERE key_id = ?1 AND app_id = ?2",
                    params![key_id, app_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(|error| unavailable("reload App Attest counter", error))?
                .map(sqlite_counter)
                .transpose()?;
            if current != snapshot.previous_app_attest_counter {
                return Err(MobileChallengeError::Invalid(
                    "App Attest counter state changed during verification".to_string(),
                ));
            }
            if current.is_some_and(|previous| counter <= previous) {
                return Err(MobileChallengeError::Attestation(
                    AttestationError::CounterRollback,
                ));
            }
            if current.is_none() {
                let retained: i64 = transaction
                    .query_row("SELECT COUNT(*) FROM chio_app_attest_counters", [], |row| {
                        row.get(0)
                    })
                    .map_err(|error| unavailable("count App Attest counters", error))?;
                let retained = usize::try_from(retained).map_err(|error| {
                    MobileChallengeError::StoreUnavailable(format!(
                        "App Attest counter count overflowed: {error}"
                    ))
                })?;
                if retained >= max_counters {
                    return Err(MobileChallengeError::StoreUnavailable(
                        "App Attest counter capacity was exhausted".to_string(),
                    ));
                }
            }
            transaction
                .execute(
                    "INSERT INTO chio_app_attest_counters (key_id, app_id, counter)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (key_id, app_id) DO UPDATE SET counter = excluded.counter",
                    params![key_id, app_id, i64::from(counter)],
                )
                .map_err(|error| unavailable("advance App Attest counter", error))?;
            Ok(())
        }
        None if verified_app_attest_counter.is_none() => Ok(()),
        None => Err(MobileChallengeError::Invalid(
            "Play Integrity evidence cannot advance an App Attest counter".to_string(),
        )),
    }
}

fn canonical_challenge_json(
    challenge: &IssuedMobileChallenge,
) -> Result<String, MobileChallengeError> {
    let bytes = chio_core_types::canonical_json_bytes(challenge).map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!(
            "challenge canonical encoding failed: {error}"
        ))
    })?;
    String::from_utf8(bytes).map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!(
            "challenge canonical JSON was not UTF-8: {error}"
        ))
    })
}

fn decode_challenge_json(value: &str) -> Result<IssuedMobileChallenge, MobileChallengeError> {
    let challenge: IssuedMobileChallenge = serde_json::from_str(value).map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!("stored challenge decoding failed: {error}"))
    })?;
    challenge.validate().map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!(
            "stored challenge validation failed: {error}"
        ))
    })?;
    if canonical_challenge_json(&challenge)?.as_bytes() != value.as_bytes() {
        return Err(MobileChallengeError::StoreUnavailable(
            "stored challenge is not canonical JSON".to_string(),
        ));
    }
    Ok(challenge)
}

fn ensure_sqlite_record_active(
    challenge: &IssuedMobileChallenge,
    consumed_at: Option<i64>,
    now_unix_seconds: u64,
) -> Result<(), MobileChallengeError> {
    if consumed_at.is_some() {
        return Err(MobileChallengeError::Replayed {
            challenge_id: challenge.challenge_id.clone(),
        });
    }
    if now_unix_seconds < challenge.issued_at_unix_seconds
        || now_unix_seconds >= challenge.expires_at_unix_seconds
    {
        return Err(MobileChallengeError::Invalid(
            "challenge is outside its validity window".to_string(),
        ));
    }
    Ok(())
}

fn sqlite_i64(value: u64, label: &str) -> Result<i64, MobileChallengeError> {
    i64::try_from(value).map_err(|error| {
        MobileChallengeError::Invalid(format!("{label} exceeds SQLite range: {error}"))
    })
}

fn sqlite_counter(value: i64) -> Result<u32, MobileChallengeError> {
    u32::try_from(value).map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!(
            "stored App Attest counter is invalid: {error}"
        ))
    })
}

fn validate_database_path(path: &Path) -> Result<(), MobileChallengeError> {
    let normalized = path.components().all(|component| {
        matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )
    });
    if !path.is_absolute()
        || path.file_name().is_none()
        || !normalized
        || path.to_string_lossy().starts_with("file:")
        || path.to_string_lossy() == ":memory:"
    {
        return Err(MobileChallengeError::Invalid(
            "mobile challenge database path must be an absolute normalized file path".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_database_custody(path: &Path) -> Result<DatabaseCustody, MobileChallengeError> {
    use std::os::unix::fs::MetadataExt as _;

    validate_database_parent(path)?;
    let owned_fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!(
            "securely open mobile challenge database file: {error}"
        ))
    })?;
    let file = std::fs::File::from(owned_fd);
    let metadata = file.metadata().map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!(
            "mobile challenge database descriptor metadata failed: {error}"
        ))
    })?;
    validate_database_metadata(&metadata)?;
    let custody = DatabaseCustody {
        path: path.to_path_buf(),
        file,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    custody.validate()?;
    Ok(custody)
}

#[cfg(not(unix))]
fn prepare_database_custody(_path: &Path) -> Result<DatabaseCustody, MobileChallengeError> {
    Err(MobileChallengeError::StoreUnavailable(
        "mobile challenge database custody requires Unix file identity".to_string(),
    ))
}

#[cfg(unix)]
fn validate_database_parent(path: &Path) -> Result<(), MobileChallengeError> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path.parent().ok_or_else(|| {
        MobileChallengeError::Invalid(
            "mobile challenge database path has no parent directory".to_string(),
        )
    })?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!(
            "mobile challenge database parent canonicalization failed: {error}"
        ))
    })?;
    if canonical_parent != parent {
        return Err(MobileChallengeError::Invalid(
            "mobile challenge database parent must not traverse symbolic links".to_string(),
        ));
    }
    let metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        MobileChallengeError::StoreUnavailable(format!(
            "mobile challenge database parent metadata failed: {error}"
        ))
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(MobileChallengeError::Invalid(format!(
            "mobile challenge database parent has unsafe ownership or permissions \
             (owner {}, expected {}, mode {:o})",
            metadata.uid(),
            rustix::process::geteuid().as_raw(),
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_database_metadata(metadata: &std::fs::Metadata) -> Result<(), MobileChallengeError> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(MobileChallengeError::StoreUnavailable(
            "mobile challenge database file has unsafe ownership or permissions".to_string(),
        ));
    }
    Ok(())
}

fn unavailable(context: &str, error: rusqlite::Error) -> MobileChallengeError {
    MobileChallengeError::StoreUnavailable(format!("{context}: {error}"))
}
