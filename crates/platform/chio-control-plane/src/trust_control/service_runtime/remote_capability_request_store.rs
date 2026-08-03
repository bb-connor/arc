#[cfg(test)]
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::{canonical_json_bytes, canonical_json_bytes_from_str};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use super::*;

const PENDING_REQUEST_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS remote_capability_pending_requests (
    pending_identity TEXT PRIMARY KEY
        CHECK (length(pending_identity) = 64),
    request_sha256 TEXT NOT NULL
        CHECK (length(request_sha256) = 64),
    canonical_request BLOB NOT NULL
        CHECK (length(canonical_request) > 0 AND length(canonical_request) <= 2097152),
    recovery_expires_at INTEGER NOT NULL
        CHECK (recovery_expires_at > 0)
) WITHOUT ROWID;
"#;
#[cfg(test)]
const TEST_MEMORY_PENDING_REQUEST_LIMIT: usize = 1_024;

#[derive(Clone)]
pub(crate) struct StoredRemoteCapabilityRequest {
    pub(crate) request: IssueCapabilityRequest,
    pub(crate) canonical_request: Vec<u8>,
    pub(crate) recovery_expires_at: u64,
}

pub(crate) struct StoredRemoteCapabilityRequestSelection {
    pub(crate) stored: StoredRemoteCapabilityRequest,
    pub(crate) inserted: bool,
}

pub(crate) trait RemoteCapabilityRequestStore: Send + Sync {
    fn load(
        &self,
        pending_identity: &str,
        now: u64,
    ) -> Result<Option<StoredRemoteCapabilityRequest>, String>;

    fn load_or_insert(
        &self,
        pending_identity: &str,
        candidate: &IssueCapabilityRequest,
        recovery_expires_at: u64,
        now: u64,
    ) -> Result<StoredRemoteCapabilityRequestSelection, String>;

    fn remove_if_exact(
        &self,
        pending_identity: &str,
        canonical_request: &[u8],
        recovery_expires_at: u64,
    ) -> Result<(), String>;
}

pub(crate) trait RemoteCapabilityIssuanceClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, String>;
}

pub(crate) struct SystemRemoteCapabilityIssuanceClock;

impl RemoteCapabilityIssuanceClock for SystemRemoteCapabilityIssuanceClock {
    fn now_unix_seconds(&self) -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| "system clock is before the Unix epoch".to_string())
    }
}

pub(crate) struct SqliteRemoteCapabilityRequestStore {
    connection: Mutex<Connection>,
}

impl SqliteRemoteCapabilityRequestStore {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage_error)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage_error)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA trusted_schema = OFF;",
            )
            .map_err(storage_error)?;
        connection
            .execute_batch(PENDING_REQUEST_SCHEMA)
            .map_err(storage_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.connection.lock().map_err(|_| {
            "remote capability pending-request database lock is unavailable".to_string()
        })
    }
}

impl RemoteCapabilityRequestStore for SqliteRemoteCapabilityRequestStore {
    fn load(
        &self,
        pending_identity: &str,
        now: u64,
    ) -> Result<Option<StoredRemoteCapabilityRequest>, String> {
        validate_pending_identity(pending_identity)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let stored = load_transaction_record(&transaction, pending_identity)?;
        let result = match stored {
            Some(stored) => {
                let stored = decode_record(stored)?;
                if stored.recovery_expires_at <= now {
                    delete_exact_transaction_record(&transaction, pending_identity, &stored)?;
                    None
                } else {
                    Some(stored)
                }
            }
            None => None,
        };
        transaction.commit().map_err(storage_error)?;
        Ok(result)
    }

    fn load_or_insert(
        &self,
        pending_identity: &str,
        candidate: &IssueCapabilityRequest,
        recovery_expires_at: u64,
        now: u64,
    ) -> Result<StoredRemoteCapabilityRequestSelection, String> {
        validate_pending_identity(pending_identity)?;
        let candidate = encode_candidate(candidate, recovery_expires_at)?;
        if candidate.recovery_expires_at <= now {
            return Err(
                "remote capability pending request is already outside its recovery window"
                    .to_string(),
            );
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        if let Some(stored) = load_transaction_record(&transaction, pending_identity)? {
            let stored = decode_record(stored)?;
            if stored.recovery_expires_at > now {
                transaction.commit().map_err(storage_error)?;
                return Ok(StoredRemoteCapabilityRequestSelection {
                    stored,
                    inserted: false,
                });
            }
            delete_exact_transaction_record(&transaction, pending_identity, &stored)?;
        }
        transaction
            .execute(
                "INSERT INTO remote_capability_pending_requests (pending_identity, request_sha256, canonical_request, recovery_expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    pending_identity,
                    chio_core::sha256_hex(&candidate.canonical_request),
                    candidate.canonical_request,
                    sqlite_i64(candidate.recovery_expires_at)?,
                ],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(StoredRemoteCapabilityRequestSelection {
            stored: candidate,
            inserted: true,
        })
    }

    fn remove_if_exact(
        &self,
        pending_identity: &str,
        canonical_request: &[u8],
        recovery_expires_at: u64,
    ) -> Result<(), String> {
        validate_pending_identity(pending_identity)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let Some(stored) = load_transaction_record(&transaction, pending_identity)? else {
            transaction.commit().map_err(storage_error)?;
            return Ok(());
        };
        let stored = decode_record(stored)?;
        if stored.canonical_request != canonical_request
            || stored.recovery_expires_at != recovery_expires_at
        {
            return Err(
                "remote capability pending-request conditional removal found different state"
                    .to_string(),
            );
        }
        delete_exact_transaction_record(&transaction, pending_identity, &stored)?;
        transaction.commit().map_err(storage_error)
    }
}

struct EncodedDatabaseRecord {
    request_sha256: String,
    canonical_request: Vec<u8>,
    recovery_expires_at: i64,
}

fn load_transaction_record(
    transaction: &Transaction<'_>,
    pending_identity: &str,
) -> Result<Option<EncodedDatabaseRecord>, String> {
    transaction
        .query_row(
            "SELECT request_sha256, canonical_request, recovery_expires_at FROM remote_capability_pending_requests WHERE pending_identity = ?1",
            params![pending_identity],
            |row| {
                Ok(EncodedDatabaseRecord {
                    request_sha256: row.get(0)?,
                    canonical_request: row.get(1)?,
                    recovery_expires_at: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(storage_error)
}

fn delete_exact_transaction_record(
    transaction: &Transaction<'_>,
    pending_identity: &str,
    stored: &StoredRemoteCapabilityRequest,
) -> Result<(), String> {
    let removed = transaction
        .execute(
            "DELETE FROM remote_capability_pending_requests WHERE pending_identity = ?1 AND request_sha256 = ?2 AND canonical_request = ?3 AND recovery_expires_at = ?4",
            params![
                pending_identity,
                chio_core::sha256_hex(&stored.canonical_request),
                stored.canonical_request,
                sqlite_i64(stored.recovery_expires_at)?,
            ],
        )
        .map_err(storage_error)?;
    if removed != 1 {
        return Err(
            "remote capability pending-request state changed during conditional removal"
                .to_string(),
        );
    }
    Ok(())
}

fn encode_candidate(
    request: &IssueCapabilityRequest,
    recovery_expires_at: u64,
) -> Result<StoredRemoteCapabilityRequest, String> {
    request.validate_structure_and_signature()?;
    let expected_expiry = request_recovery_expiry(request)?;
    if recovery_expires_at != expected_expiry {
        return Err("remote capability pending-request recovery expiry mismatch".to_string());
    }
    let canonical_request = canonical_json_bytes(request).map_err(|error| {
        format!("remote capability pending request cannot be canonicalized: {error}")
    })?;
    if canonical_request.len() > CAPABILITY_ISSUANCE_RESPONSE_MAX_BYTES as usize {
        return Err("remote capability pending request exceeds its byte limit".to_string());
    }
    Ok(StoredRemoteCapabilityRequest {
        request: request.clone(),
        canonical_request,
        recovery_expires_at,
    })
}

fn decode_record(record: EncodedDatabaseRecord) -> Result<StoredRemoteCapabilityRequest, String> {
    if record.canonical_request.is_empty()
        || record.canonical_request.len() > CAPABILITY_ISSUANCE_RESPONSE_MAX_BYTES as usize
    {
        return Err("remote capability pending request has an invalid byte length".to_string());
    }
    if chio_core::sha256_hex(&record.canonical_request) != record.request_sha256 {
        return Err("remote capability pending-request digest mismatch".to_string());
    }
    let raw = std::str::from_utf8(&record.canonical_request)
        .map_err(|_| "remote capability pending request is not UTF-8".to_string())?;
    let canonical = canonical_json_bytes_from_str(raw)
        .map_err(|_| "remote capability pending request is not strict I-JSON".to_string())?;
    if canonical != record.canonical_request {
        return Err("remote capability pending request is not canonical".to_string());
    }
    let request: IssueCapabilityRequest = serde_json::from_slice(&canonical)
        .map_err(|_| "remote capability pending request cannot be decoded".to_string())?;
    request.validate_structure_and_signature()?;
    if canonical_json_bytes(&request).map_err(|error| error.to_string())? != canonical {
        return Err("remote capability pending request contains non-schema material".to_string());
    }
    let recovery_expires_at = sqlite_u64(record.recovery_expires_at)?;
    if request_recovery_expiry(&request)? != recovery_expires_at {
        return Err("remote capability pending-request recovery expiry is corrupt".to_string());
    }
    Ok(StoredRemoteCapabilityRequest {
        request,
        canonical_request: canonical,
        recovery_expires_at,
    })
}

pub(crate) fn request_recovery_expiry(request: &IssueCapabilityRequest) -> Result<u64, String> {
    request
        .requested_at
        .checked_add(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
        .and_then(|value| value.checked_add(request.ttl_seconds))
        .ok_or_else(|| "remote capability pending-request recovery expiry overflows".to_string())
}

fn validate_pending_identity(pending_identity: &str) -> Result<(), String> {
    if pending_identity.len() != 64
        || !pending_identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("remote capability pending-request identity is invalid".to_string());
    }
    Ok(())
}

fn sqlite_i64(value: u64) -> Result<i64, String> {
    i64::try_from(value)
        .map_err(|_| "remote capability pending-request timestamp exceeds SQLite".to_string())
}

fn sqlite_u64(value: i64) -> Result<u64, String> {
    u64::try_from(value)
        .map_err(|_| "remote capability pending-request timestamp is negative".to_string())
}

fn storage_error(_error: rusqlite::Error) -> String {
    "remote capability pending-request database is unavailable".to_string()
}

#[cfg(test)]
pub(crate) struct BoundedMemoryRemoteCapabilityRequestStore {
    entries: Mutex<HashMap<String, StoredRemoteCapabilityRequest>>,
    capacity: usize,
}

#[cfg(test)]
impl BoundedMemoryRemoteCapabilityRequestStore {
    pub(crate) fn for_test() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: TEST_MEMORY_PENDING_REQUEST_LIMIT,
        }
    }
}

#[cfg(test)]
impl RemoteCapabilityRequestStore for BoundedMemoryRemoteCapabilityRequestStore {
    fn load(
        &self,
        pending_identity: &str,
        now: u64,
    ) -> Result<Option<StoredRemoteCapabilityRequest>, String> {
        validate_pending_identity(pending_identity)?;
        let mut entries = self.entries.lock().map_err(|_| {
            "remote capability pending-request memory lock is unavailable".to_string()
        })?;
        let Some(stored) = entries.get(pending_identity).cloned() else {
            return Ok(None);
        };
        validate_memory_record(&stored)?;
        if stored.recovery_expires_at <= now {
            entries.remove(pending_identity);
            return Ok(None);
        }
        Ok(Some(stored))
    }

    fn load_or_insert(
        &self,
        pending_identity: &str,
        candidate: &IssueCapabilityRequest,
        recovery_expires_at: u64,
        now: u64,
    ) -> Result<StoredRemoteCapabilityRequestSelection, String> {
        validate_pending_identity(pending_identity)?;
        let candidate = encode_candidate(candidate, recovery_expires_at)?;
        if candidate.recovery_expires_at <= now {
            return Err(
                "remote capability pending request is already outside its recovery window"
                    .to_string(),
            );
        }
        let mut entries = self.entries.lock().map_err(|_| {
            "remote capability pending-request memory lock is unavailable".to_string()
        })?;
        if let Some(stored) = entries.get(pending_identity).cloned() {
            validate_memory_record(&stored)?;
            if stored.recovery_expires_at > now {
                return Ok(StoredRemoteCapabilityRequestSelection {
                    stored,
                    inserted: false,
                });
            }
            entries.remove(pending_identity);
        }
        entries.retain(|_, stored| stored.recovery_expires_at > now);
        if entries.len() >= self.capacity {
            return Err("remote capability pending-request memory bound is exhausted".to_string());
        }
        entries.insert(pending_identity.to_string(), candidate.clone());
        Ok(StoredRemoteCapabilityRequestSelection {
            stored: candidate,
            inserted: true,
        })
    }

    fn remove_if_exact(
        &self,
        pending_identity: &str,
        canonical_request: &[u8],
        recovery_expires_at: u64,
    ) -> Result<(), String> {
        validate_pending_identity(pending_identity)?;
        let mut entries = self.entries.lock().map_err(|_| {
            "remote capability pending-request memory lock is unavailable".to_string()
        })?;
        let Some(stored) = entries.get(pending_identity) else {
            return Ok(());
        };
        validate_memory_record(stored)?;
        if stored.canonical_request != canonical_request
            || stored.recovery_expires_at != recovery_expires_at
        {
            return Err(
                "remote capability pending-request conditional removal found different state"
                    .to_string(),
            );
        }
        entries.remove(pending_identity);
        Ok(())
    }
}

#[cfg(test)]
fn validate_memory_record(stored: &StoredRemoteCapabilityRequest) -> Result<(), String> {
    let expected = encode_candidate(&stored.request, stored.recovery_expires_at)?;
    if expected.canonical_request != stored.canonical_request {
        return Err("remote capability pending-request memory state is corrupt".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;
    use std::sync::Arc;

    const REQUESTED_AT: u64 = 10_000;
    const REQUEST_TTL: u64 = 300;

    fn pending_identity() -> String {
        "17".repeat(32)
    }

    fn request(nonce_byte: &str) -> IssueCapabilityRequest {
        let workload_signer = Keypair::from_seed(&[31_u8; 32]);
        let session_signer = Keypair::from_seed(&[32_u8; 32]);
        let authority = Keypair::from_seed(&[33_u8; 32]);
        let subject = Keypair::from_seed(&[34_u8; 32]);
        IssueCapabilityRequest::new(
            nonce_byte.repeat(32),
            REQUESTED_AT,
            chio_security_types::ports::TenantId::new("tenant-pending-store").test_unwrap(),
            chio_security_types::ports::LineageId::new("lineage-pending-store").test_unwrap(),
            "session-pending-store".to_string(),
            "principal-pending-store".to_string(),
            "isolation-pending-store".to_string(),
            1,
            "workload-pending-store".to_string(),
            "server-pending-store".to_string(),
            authority.public_key(),
            1,
            &subject.public_key(),
            ChioScope::default(),
            REQUEST_TTL,
            None,
            &workload_signer,
            &session_signer,
        )
        .test_unwrap()
    }

    fn sqlite_store() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        SqliteRemoteCapabilityRequestStore,
    ) {
        let directory = tempfile::tempdir().test_unwrap();
        let path = directory.path().join("verifier.sqlite3");
        drop(Connection::open(&path).test_unwrap());
        let store = SqliteRemoteCapabilityRequestStore::open(&path).test_unwrap();
        (directory, path, store)
    }

    #[test]
    fn sqlite_pending_request_survives_store_reconstruction() {
        let (_directory, path, store) = sqlite_store();
        let request = request("aa");
        let expiry = request_recovery_expiry(&request).test_unwrap();
        let inserted = store
            .load_or_insert(&pending_identity(), &request, expiry, REQUESTED_AT)
            .test_unwrap();
        assert!(inserted.inserted);
        drop(store);

        let reopened = SqliteRemoteCapabilityRequestStore::open(&path).test_unwrap();
        let recovered = reopened
            .load(&pending_identity(), REQUESTED_AT + 61)
            .test_unwrap()
            .test_expect("persisted exact request");
        assert_eq!(recovered.request.request_nonce, request.request_nonce);
        assert_eq!(
            recovered.canonical_request,
            canonical_json_bytes(&request).test_unwrap()
        );
    }

    #[test]
    fn sqlite_pending_request_rejects_corrupt_bytes_and_expiry() {
        for corrupt_expiry in [false, true] {
            let (_directory, path, store) = sqlite_store();
            let request = request("ab");
            let expiry = request_recovery_expiry(&request).test_unwrap();
            store
                .load_or_insert(&pending_identity(), &request, expiry, REQUESTED_AT)
                .test_unwrap();
            let connection = Connection::open(&path).test_unwrap();
            if corrupt_expiry {
                connection
                    .execute(
                        "UPDATE remote_capability_pending_requests SET recovery_expires_at = recovery_expires_at + 1 WHERE pending_identity = ?1",
                        params![pending_identity()],
                    )
                    .test_unwrap();
            } else {
                connection
                    .execute(
                        "UPDATE remote_capability_pending_requests SET canonical_request = ?1 WHERE pending_identity = ?2",
                        params![b"{}".as_slice(), pending_identity()],
                    )
                    .test_unwrap();
            }
            assert!(store.load(&pending_identity(), REQUESTED_AT).is_err());
        }
    }

    #[test]
    fn sqlite_pending_request_conditional_remove_rejects_mismatch() {
        let (_directory, _path, store) = sqlite_store();
        let first = request("ac");
        let different = request("ad");
        let expiry = request_recovery_expiry(&first).test_unwrap();
        store
            .load_or_insert(&pending_identity(), &first, expiry, REQUESTED_AT)
            .test_unwrap();
        let different_canonical = canonical_json_bytes(&different).test_unwrap();
        let error = store
            .remove_if_exact(&pending_identity(), &different_canonical, expiry)
            .test_unwrap_err();
        assert!(error.contains("different state"));
        assert!(store
            .load(&pending_identity(), REQUESTED_AT)
            .test_unwrap()
            .is_some());
    }

    #[test]
    fn sqlite_pending_request_expires_only_at_full_recovery_horizon() {
        let (_directory, _path, store) = sqlite_store();
        let request = request("ae");
        let expiry = request_recovery_expiry(&request).test_unwrap();
        assert_eq!(
            expiry,
            REQUESTED_AT + CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS + REQUEST_TTL
        );
        store
            .load_or_insert(&pending_identity(), &request, expiry, REQUESTED_AT)
            .test_unwrap();
        assert!(store
            .load(&pending_identity(), expiry - 1)
            .test_unwrap()
            .is_some());
        assert!(store
            .load(&pending_identity(), expiry)
            .test_unwrap()
            .is_none());
    }

    #[test]
    fn sqlite_pending_request_fails_closed_on_store_outage() {
        let (_directory, path, store) = sqlite_store();
        Connection::open(&path)
            .test_unwrap()
            .execute_batch("DROP TABLE remote_capability_pending_requests;")
            .test_unwrap();
        let error = store
            .load(&pending_identity(), REQUESTED_AT)
            .test_unwrap_err();
        assert!(error.contains("database is unavailable"));
    }

    #[test]
    fn sqlite_pending_request_concurrent_cas_selects_one_exact_request() {
        let (_directory, path, first_store) = sqlite_store();
        let mut stores = vec![first_store];
        for _ in 1..8 {
            stores.push(SqliteRemoteCapabilityRequestStore::open(&path).test_unwrap());
        }
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();
        for (index, store) in (0_u8..8).zip(stores) {
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let request = request(&format!("{index:02x}"));
                let expiry = request_recovery_expiry(&request).test_unwrap();
                barrier.wait();
                store
                    .load_or_insert(&pending_identity(), &request, expiry, REQUESTED_AT)
                    .test_unwrap()
                    .stored
                    .canonical_request
            }));
        }
        let selected = threads
            .into_iter()
            .map(|thread| thread.join().test_unwrap())
            .collect::<Vec<_>>();
        assert!(selected.windows(2).all(|window| window[0] == window[1]));
    }
}
