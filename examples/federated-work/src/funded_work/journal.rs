use super::{
    agreement::{Policy, SignedAgreement},
    observer::VerifiedAllocation,
};
use crate::common::{digest, Result};
use chio_kernel::ToolCallRequest;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    fs::OpenOptions,
    path::Path,
    sync::{Mutex, MutexGuard},
};

// Leave one native retention slot available for recovery administration.
pub const CAPACITY: usize = 63;

pub struct Journal(Mutex<Connection>, usize);

pub struct Entry {
    pub allocation: String,
    pub agreement: SignedAgreement,
    pub request: ToolCallRequest,
    pub operation: Option<String>,
    pub hold: Option<String>,
}

struct StoredEntry {
    allocation: String,
    agreement: String,
    request: String,
    operation: Option<String>,
    hold: Option<String>,
}

impl Journal {
    pub fn provision(path: &Path, policy: &Policy) -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?.sync_all()?;
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            BEGIN IMMEDIATE;
            CREATE TABLE identity(policy_digest TEXT NOT NULL);
            CREATE TABLE allocations(
                allocation TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                agreement TEXT NOT NULL, request TEXT NOT NULL,
                observation_digest TEXT NOT NULL, observed_at INTEGER NOT NULL,
                operation TEXT UNIQUE, hold TEXT UNIQUE,
                CHECK((operation IS NULL) = (hold IS NULL)));
            CREATE TABLE executions(sequence INTEGER PRIMARY KEY, output TEXT NOT NULL);
            CREATE TABLE custody(digest TEXT PRIMARY KEY, bytes BLOB NOT NULL);
            CREATE TABLE records(allocation TEXT NOT NULL REFERENCES allocations(allocation),
                kind TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(allocation,kind));
            PRAGMA user_version=2;",
        )?;
        connection.execute("INSERT INTO identity VALUES(?1)", [digest(policy)?])?;
        connection.execute_batch("COMMIT;")?;
        Ok(())
    }

    pub fn open(path: &Path, policy: &Policy) -> Result<Self> {
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err("funding journal must be an existing regular file".into());
        }
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let pins: Vec<String> = connection
            .prepare("SELECT policy_digest FROM identity")?
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        if version != 2 || pins != [digest(policy)?] {
            return Err("funding journal owner or version mismatch".into());
        }
        // The execution profile pins one single-leaf checkpoint log before
        // agreement. Refuse a second allocation before any native dispatch.
        let capacity = if super::execution_evidence::enabled(policy) {
            1
        } else {
            CAPACITY
        };
        Ok(Self(Mutex::new(connection), capacity))
    }

    pub(super) fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.0
            .lock()
            .map_err(|_| "funding journal lock poisoned".into())
    }

    pub fn stage(
        &self,
        verified: &VerifiedAllocation,
        agreement: &SignedAgreement,
        request: &ToolCallRequest,
    ) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let agreement_bytes = String::from_utf8(chio_core_types::canonical_json_bytes(agreement)?)?;
        let request_bytes = String::from_utf8(chio_core_types::canonical_json_bytes(request)?)?;
        let existing: Option<(String, String, String)> = transaction.query_row(
            "SELECT allocation,agreement,request FROM allocations WHERE allocation=?1 OR request_id=?2",
            params![verified.id, request.request_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
        if let Some((allocation, stored_agreement, stored_request)) = existing {
            if allocation != verified.id
                || stored_agreement != agreement_bytes
                || stored_request != request_bytes
            {
                return Err(
                    "allocation already bound to another agreement or native request".into(),
                );
            }
        } else {
            let count: i64 =
                transaction.query_row("SELECT count(*) FROM allocations", [], |r| r.get(0))?;
            if usize::try_from(count)? >= self.1 {
                return Err("funding retention capacity exhausted".into());
            }
            transaction.execute("INSERT INTO allocations(allocation,request_id,agreement,request,observation_digest,observed_at)
                VALUES(?1,?2,?3,?4,?5,?6)", params![verified.id, request.request_id, agreement_bytes,
                    request_bytes, verified.observation_digest, i64::try_from(verified.observed_at)?])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn by_request(&self, request_id: &str) -> Result<Option<Entry>> {
        let connection = self.connection()?;
        let row: Option<StoredEntry> = connection.query_row(
            "SELECT allocation,agreement,request,operation,hold FROM allocations WHERE request_id=?1",
            [request_id], |r| Ok(StoredEntry {
                allocation: r.get(0)?, agreement: r.get(1)?, request: r.get(2)?,
                operation: r.get(3)?, hold: r.get(4)?,
            })).optional()?;
        row.map(|stored| {
            Ok(Entry {
                allocation: stored.allocation,
                agreement: super::evidence::decode(stored.agreement.as_bytes())?,
                request: super::evidence::decode(stored.request.as_bytes())?,
                operation: stored.operation,
                hold: stored.hold,
            })
        })
        .transpose()
    }

    pub fn by_operation(&self, operation: &str) -> Result<Option<Entry>> {
        let request: Option<String> = self
            .connection()?
            .query_row(
                "SELECT request_id FROM allocations WHERE operation=?1",
                [operation],
                |r| r.get(0),
            )
            .optional()?;
        request
            .map(|id| self.by_request(&id))
            .transpose()
            .map(Option::flatten)
    }

    /// This commit closes the native-journal/rail-acknowledgement gap. Neither
    /// identifier can ever be reassigned, including after financial closure.
    pub fn bind(&self, allocation: &str, operation: &str, hold: &str) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE allocations SET operation=?2,hold=?3 WHERE allocation=?1
            AND ((operation IS NULL AND hold IS NULL) OR (operation=?2 AND hold=?3))",
            params![allocation, operation, hold],
        )?;
        if changed != 1 {
            return Err("funding operation or original hold conflict".into());
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn record_output(&self, output: &serde_json::Value) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO executions(output) VALUES(?1)",
            [serde_json::to_string(output)?],
        )?;
        Ok(())
    }

    pub fn execution_count(&self) -> Result<u64> {
        let count: i64 =
            self.connection()?
                .query_row("SELECT count(*) FROM executions", [], |r| r.get(0))?;
        Ok(u64::try_from(count)?)
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        if bytes.is_empty() || bytes.len() > 256 * 1024 {
            return Err("custody object exceeds profile".into());
        }
        let hash = chio_core_types::sha256_hex(bytes);
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = tx
            .query_row("SELECT bytes FROM custody WHERE digest=?1", [&hash], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(stored) = existing {
            if stored != bytes {
                return Err("custody content address conflict".into());
            }
            tx.commit()?;
            return Ok(hash);
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM custody", [], |r| r.get(0))?;
        if count >= i64::try_from(CAPACITY * 8)? {
            return Err("custody capacity exhausted".into());
        }
        tx.execute(
            "INSERT OR IGNORE INTO custody VALUES(?1,?2)",
            params![hash, bytes],
        )?;
        let stored: Vec<u8> =
            tx.query_row("SELECT bytes FROM custody WHERE digest=?1", [&hash], |r| {
                r.get(0)
            })?;
        if stored != bytes {
            return Err("custody content address conflict".into());
        }
        tx.commit()?;
        Ok(hash)
    }

    pub fn blob(&self, hash: &str) -> Result<Vec<u8>> {
        let bytes: Vec<u8> = self.connection()?.query_row(
            "SELECT bytes FROM custody WHERE digest=?1",
            [hash],
            |r| r.get(0),
        )?;
        if bytes.is_empty()
            || bytes.len() > 256 * 1024
            || chio_core_types::sha256_hex(&bytes) != hash
        {
            return Err("custody bytes do not match content address".into());
        }
        Ok(bytes)
    }

    /// Insert once, compare exact bytes on every retry. Never replace an intent
    /// after an uncertain external effect, even with another valid signature.
    pub fn retain<T: serde::Serialize>(
        &self,
        allocation: &str,
        kind: &str,
        value: &T,
    ) -> Result<()> {
        let bytes = chio_core_types::canonical_json_bytes(value)?;
        if bytes.len() > 256 * 1024
            || !matches!(
                kind,
                "submission"
                    | "execution-evidence"
                    | "execution-checkpoint"
                    | "capture-waiver"
                    | "decision"
                    | "submit"
                    | "record"
                    | "pay"
                    | "refund"
                    | "submit-observed"
                    | "record-observed"
                    | "pay-observed"
                    | "refund-observed"
            )
        {
            return Err("unsupported lifecycle record".into());
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO records VALUES(?1,?2,?3)",
            params![allocation, kind, bytes],
        )?;
        let stored: Vec<u8> = tx.query_row(
            "SELECT payload FROM records WHERE allocation=?1 AND kind=?2",
            params![allocation, kind],
            |r| r.get(0),
        )?;
        if stored != bytes {
            return Err("conflicting retained lifecycle identity".into());
        }
        tx.commit()?;
        Ok(())
    }

    pub fn retained<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        allocation: &str,
        kind: &str,
    ) -> Result<Option<T>> {
        let bytes: Option<Vec<u8>> = self
            .connection()?
            .query_row(
                "SELECT payload FROM records WHERE allocation=?1 AND kind=?2",
                params![allocation, kind],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| super::evidence::decode(&bytes))
            .transpose()
    }
}
