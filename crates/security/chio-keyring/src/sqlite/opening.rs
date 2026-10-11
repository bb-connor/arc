//! Durable key-log storage composition.
use super::*;

impl SqliteKeyLogStore {
    pub fn open(path: impl AsRef<Path>, policy: KeyLogPolicy) -> Result<Self> {
        Self::open_with_clock(
            path,
            policy,
            SigningTopology::LocalSingleWriter,
            Arc::new(SystemClock),
        )
    }

    pub fn open_existing(path: impl AsRef<Path>, policy: KeyLogPolicy) -> Result<Self> {
        Self::open_existing_with_clock(path, policy, Arc::new(SystemClock))
    }

    pub fn open_existing_with_clock(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        clock.unix_millis()?;
        let path = path.as_ref();
        crate::require_existing_durable_sqlite_path(path)?;
        Self::open_with_clock(path, policy, SigningTopology::LocalSingleWriter, clock)
    }

    /// Opens a strictly read-only view without acquiring the selector-writer
    /// fence. Observers can verify durable history but cannot mutate the
    /// authoritative key selector.
    pub fn open_observer(path: impl AsRef<Path>, policy: KeyLogPolicy) -> Result<Self> {
        let path = path.as_ref();
        crate::require_existing_durable_sqlite_path(path)?;
        let storage_file = crate::open_durable_sqlite_file(path, false, false)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        storage_file.validate_live_connection(&connection)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA query_only = ON;")?;
        let durable_state_exists = durable_state_exists(&connection)?;
        crate::persist_or_validate_policy_binding(&connection, &policy, durable_state_exists)?;
        let store = Self {
            connection: Mutex::new(connection),
            policy,
            clock: Arc::new(SystemClock),
            storage_file,
            _selector_lock: None,
        };
        store.validate_startup()?;
        Ok(store)
    }

    pub fn open_with_topology(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        topology: SigningTopology,
    ) -> Result<Self> {
        Self::open_with_clock(path, policy, topology, Arc::new(SystemClock))
    }

    pub fn open_with_clock(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        topology: SigningTopology,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let path = path.as_ref();
        if topology != SigningTopology::LocalSingleWriter {
            return Err(KeyringError::StateInvariant(
                "local SQLite selector supports one signing writer",
            ));
        }
        let storage_file = crate::open_durable_sqlite_file(path, true, true)?;
        let selector_lock = acquire_selector_writer_lock(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        storage_file.validate_live_connection(&connection)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
        )?;
        connection.execute_batch(SCHEMA)?;
        let durable_state_exists = durable_state_exists(&connection)?;
        crate::persist_or_validate_policy_binding(&connection, &policy, durable_state_exists)?;
        let store = Self {
            connection: Mutex::new(connection),
            policy,
            clock,
            storage_file,
            _selector_lock: Some(selector_lock),
        };
        store.validate_startup()?;
        Ok(store)
    }
}
