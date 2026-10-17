#![allow(dead_code)]

use chio_security_types::clock as trusted_time;
use chio_store_sqlite::SqliteAuthorityStore;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub struct SettableClock {
    now_unix_ms: AtomicU64,
}

impl SettableClock {
    pub fn set(&self, now_unix_ms: u64) {
        self.now_unix_ms.store(now_unix_ms, Ordering::Release);
    }
}

impl trusted_time::Clock for SettableClock {
    fn read(&self) -> Result<trusted_time::ClockReading, trusted_time::ClockError> {
        let value = self.now_unix_ms.load(Ordering::Acquire);
        trusted_time::Clock::read(&trusted_time::FixedClock::from_millis(value))
    }
}

/// A provisioned authority database that can be opened as a serving owner
/// repeatedly under one settable trusted clock.
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub database: PathBuf,
    pub locks: PathBuf,
    pub clock: Arc<SettableClock>,
}

impl Fixture {
    pub fn new(now_unix_ms: u64) -> TestResult<Self> {
        let dir = chio_test_support::private_tempdir()?;
        let database = dir.path().join("authority.sqlite");
        let locks = dir.path().join("locks");
        std::fs::DirBuilder::new().mode(0o700).create(&locks)?;
        SqliteAuthorityStore::provision(&database, &locks)?;
        Ok(Self {
            dir,
            database,
            locks,
            clock: Arc::new(SettableClock {
                now_unix_ms: AtomicU64::new(now_unix_ms),
            }),
        })
    }

    pub fn open(&self) -> TestResult<SqliteAuthorityStore> {
        Ok(SqliteAuthorityStore::open_serving_with_clock(
            &self.database,
            &self.locks,
            self.clock.clone(),
        )?)
    }

    /// Set the trusted clock and return the same instant for a mutation.
    pub fn at(&self, now_unix_ms: u64) -> u64 {
        self.clock.set(now_unix_ms);
        now_unix_ms
    }

    pub fn raw(&self) -> TestResult<rusqlite::Connection> {
        Ok(rusqlite::Connection::open(&self.database)?)
    }
}
