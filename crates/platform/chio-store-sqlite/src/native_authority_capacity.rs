//! Every writer of a native authority file preserves its finishing bank.
//!
//! The co-located authority stores write through one serving connection, and
//! every serving transaction enters the owner's gate before it writes. The
//! gate applies a page cap through SQLite's own `max_page_count` while the
//! transaction holds the connection: the file's pages plus every owed growth
//! stay within the smallest owed ceiling, and an ordinary transaction may add
//! only the pages its measured disk headroom affords. A funded writer raises
//! that cap, before its writes, by exactly the allowance its authenticated
//! purpose priced. The connection never spills, so no frame of a transaction
//! reaches the WAL before its COMMIT, and every dirty page is a page of the
//! capped file. The commit hook prices an ordinary transaction from the
//! actual row images captured by the existing preupdate ledger, including
//! indexes and trigger writes. It refuses any unpriced shape and preserves all
//! old and newly published debt. Funded writers still consume their own
//! authenticated prepaid purposes. The hook uses a separate read-only observer
//! of the held file and never runs SQL on the committing connection.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chio_sqlite_file_identity::{
    main_database_available_bytes, main_database_file_identity, require_physical_write_capacity,
    SqlitePhysicalDebtAmountData, SqliteWriteCapacityStageData,
};
use rusqlite::hooks::{Action, AuthAction, AuthContext, Authorization};
use rusqlite::Connection;

pub(crate) mod rows;

use crate::admission_operation_store::{
    native_authority_debt, native_authority_table_row_debt, observed_wal_pressure,
    AuthorityCurrentWritePrice, NativeAuthorityDebtData,
};

/// SQLite clamps a larger request to its compiled maximum page count.
const SQLITE_MAXIMUM_PAGE_COUNT: u64 = 4_294_967_294;
const FRAME_HEADER_BYTES: u64 = 24;
const WAL_HEADER_BYTES: u64 = 32;
/// A FULL commit pads its last frame to the largest supported sector.
const MAX_WAL_SECTOR_BYTES: u64 = 65_536;

/// Native mutation scopes are stricter than this policy. On leaving one they
/// restore the strict policy until the next owning gate reads the bank again.
/// No caller receives permission to alter a priced catalog while loans exist.
pub(crate) fn install_schema_guard(
    connection: &Connection,
    protected: bool,
) -> rusqlite::Result<()> {
    connection.authorizer(Some(move |context: AuthContext<'_>| {
        if !protected {
            return Authorization::Allow;
        }
        match context.action {
            AuthAction::Select
            | AuthAction::Read { .. }
            | AuthAction::Function { .. }
            | AuthAction::Recursive
            | AuthAction::Transaction { .. }
            | AuthAction::Savepoint { .. } => Authorization::Allow,
            AuthAction::Insert { table_name }
            | AuthAction::Update { table_name, .. }
            | AuthAction::Delete { table_name }
                if !table_name.starts_with("sqlite_") =>
            {
                Authorization::Allow
            }
            AuthAction::Pragma {
                pragma_value: None, ..
            } => Authorization::Allow,
            AuthAction::Pragma {
                pragma_name,
                pragma_value,
            } if [
                "table_info",
                "table_xinfo",
                "index_info",
                "index_xinfo",
                "index_list",
                "foreign_key_list",
                "max_page_count",
                "wal_checkpoint",
                "busy_timeout",
            ]
            .iter()
            .any(|allowed| pragma_name.eq_ignore_ascii_case(allowed))
                || (pragma_name.eq_ignore_ascii_case("cache_spill")
                    && pragma_value == Some("0")) =>
            {
                Authorization::Allow
            }
            _ => {
                #[cfg(feature = "admission-test-support")]
                eprintln!("native retained-catalog guard refused {:?}", context.action);
                Authorization::Deny
            }
        }
    }))
}

pub(crate) struct NativeAuthorityCapacity {
    store_uuid: String,
    path: String,
    device: u64,
    inode: u64,
    initial_page_ceiling: u64,
    state: Mutex<CapacityState>,
    refused: AtomicBool,
    row_callback_failed: AtomicBool,
}

struct CapacityState {
    /// The page cap last applied to the serving connection.
    cap: u64,
    /// The funded cap of the open transaction. It stays applied, through any
    /// later gate entry, until that transaction commits or rolls back.
    authorized: Option<u64>,
    /// The priced current write of the open ordinary transaction,
    /// `(wal_bytes, disk_bytes)`, checked before its first write.
    priced: Option<(u64, u64)>,
    /// The priced amount the open transaction spent from authenticated
    /// purposes, `(wal_bytes, disk_bytes)`.
    funded: Option<(u64, u64)>,
    observer: Option<Connection>,
    writer_profile: Option<chio_sqlite_file_identity::SqliteFramePriceProfileData>,
    rows: Option<rows::RowLedger>,
    growth_grants: BTreeSet<String>,
    /// The bank this transaction will publish. The separate observer sees
    /// only its predecessor until COMMIT, so it cannot protect newly owed work.
    committing_bank: Option<NativeAuthorityDebtData>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn pragma_u64(connection: &Connection, pragma: &str) -> Result<u64, String> {
    let value: i64 = connection
        .query_row(&format!("PRAGMA main.{pragma}"), [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    u64::try_from(value).map_err(|_| format!("native authority {pragma} is invalid"))
}

/// WAL bytes a COMMIT that never spilled can append when the file holds at
/// most `pages` pages: each dirty page once, the FULL commit padding and a
/// restarted log's header.
fn committed_wal_bound(pages: u64, page_size: u64) -> Result<u64, String> {
    let frame = page_size
        .checked_add(FRAME_HEADER_BYTES)
        .ok_or_else(|| "native authority frame size exhausted".to_owned())?;
    pages
        .checked_add(MAX_WAL_SECTOR_BYTES.div_ceil(frame))
        .and_then(|frames| frames.checked_mul(frame))
        .and_then(|bytes| bytes.checked_add(WAL_HEADER_BYTES))
        .ok_or_else(|| "native authority WAL bound exhausted".to_owned())
}

impl NativeAuthorityCapacity {
    /// The capacity of the authority file held by `connection`.
    pub(crate) fn new(connection: &Connection, store_uuid: &str) -> Result<Arc<Self>, String> {
        let path = connection
            .path()
            .ok_or_else(|| "native authority requires a persistent file".to_owned())?
            .to_owned();
        let file = main_database_file_identity(connection)?;
        let initial_page_ceiling = pragma_u64(connection, "max_page_count")?;
        Ok(Arc::new(Self {
            store_uuid: store_uuid.to_owned(),
            path,
            device: file.device,
            inode: file.inode,
            initial_page_ceiling,
            state: Mutex::new(CapacityState {
                cap: initial_page_ceiling,
                authorized: None,
                priced: None,
                funded: None,
                observer: None,
                writer_profile: None,
                rows: None,
                growth_grants: BTreeSet::new(),
                committing_bank: None,
            }),
            refused: AtomicBool::new(false),
            row_callback_failed: AtomicBool::new(false),
        }))
    }

    /// Keep every frame of the serving connection out of the WAL until its
    /// COMMIT, and check every COMMIT on it, explicit or autocommit, before
    /// any frame is written.
    pub(crate) fn install(self: &Arc<Self>, connection: &Connection) -> rusqlite::Result<()> {
        connection.execute_batch("PRAGMA main.cache_spill = 0;")?;
        let capacity = Arc::clone(self);
        connection.preupdate_hook(Some(
            move |action, database: &str, table: &str, case: &rusqlite::hooks::PreUpdateCase| {
                // The vendored callback catches panics. Latch failure before any
                // work so a swallowed panic can never allow COMMIT.
                if capacity.row_callback_failed.swap(true, Ordering::AcqRel) {
                    return;
                }
                let mut state = lock(&capacity.state);
                if let Some(rows) = &mut state.rows {
                    rows.changed(database, table, case);
                    match action {
                        Action::SQLITE_INSERT => rows.inserted(database, table),
                        Action::SQLITE_UPDATE | Action::SQLITE_DELETE => (),
                        _ => rows.fail(),
                    }
                }
                capacity.row_callback_failed.store(false, Ordering::Release);
            },
        ))?;
        let capacity = Arc::clone(self);
        connection.commit_hook(Some(move || {
            catch_unwind(AssertUnwindSafe(|| {
                capacity.refused.store(false, Ordering::Release);
                let (funded, priced, rows, committing_bank) = {
                    let mut state = lock(&capacity.state);
                    state.authorized = None;
                    state.growth_grants.clear();
                    (
                        state.funded.take(),
                        state.priced.take(),
                        state.rows.take(),
                        state.committing_bank.take(),
                    )
                };
                if capacity.row_callback_failed.load(Ordering::Acquire)
                    || rows.as_ref().is_some_and(|rows| match rows.check() {
                        Ok(()) => false,
                        Err(error) => {
                            #[cfg(feature = "admission-test-support")]
                            eprintln!("native authority COMMIT row refusal: {error}");
                            let _ = error;
                            true
                        }
                    })
                {
                    capacity.refused.store(true, Ordering::Release);
                    return true;
                }
                match capacity.permits_commit(funded, priced, rows.as_ref(), committing_bank) {
                    Ok(()) => false,
                    Err(error) => {
                        #[cfg(feature = "admission-test-support")]
                        eprintln!(
                            "native authority COMMIT capacity refusal: {error}\n{}",
                            std::backtrace::Backtrace::force_capture()
                        );
                        let _ = error;
                        capacity.refused.store(true, Ordering::Release);
                        true
                    }
                }
            }))
            .unwrap_or(true)
        }))?;
        let capacity = Arc::clone(self);
        connection.rollback_hook(Some(move || {
            let mut state = lock(&capacity.state);
            state.authorized = None;
            state.priced = None;
            state.funded = None;
            state.rows = None;
            state.writer_profile = None;
            state.growth_grants.clear();
            state.committing_bank = None;
            capacity.row_callback_failed.store(false, Ordering::Release);
        }))
    }

    /// The gate of one serving transaction, before any of its writes: apply
    /// the ordinary page cap from the authenticated bank and current headroom.
    /// A gate entered inside a funded transaction keeps its funded cap.
    pub(crate) fn begin(&self, connection: &Connection) -> Result<(), String> {
        {
            let mut state = lock(&self.state);
            if connection.is_autocommit() {
                state.authorized = None;
                state.priced = None;
                self.refused.store(false, Ordering::Release);
                state.rows = None;
                state.writer_profile = None;
                state.growth_grants.clear();
                state.committing_bank = None;
            }
            if state.authorized.is_some() {
                return Ok(());
            }
            state.funded = None;
        }
        let debts = native_authority_table_row_debt(connection, &self.store_uuid)
            .map_err(|error| error.to_string())?;
        let protects_schema = {
            let mut state = lock(&self.state);
            if state.rows.is_none() {
                state.rows = Some(rows::RowLedger::snapshot(connection, &debts)?);
            }
            state
                .rows
                .as_ref()
                .is_some_and(rows::RowLedger::protects_schema)
        };
        install_schema_guard(connection, protects_schema).map_err(|error| error.to_string())?;
        self.restore(connection)
    }

    pub(crate) fn preserve_committing_bank(
        &self,
        connection: &Connection,
        debts: &BTreeMap<String, rows::NativeTableRowDebt>,
    ) -> Result<(), String> {
        let committing_bank = native_authority_debt(connection, &self.store_uuid, self.device)
            .map_err(|error| error.to_string())?;
        let mut state = lock(&self.state);
        state
            .rows
            .get_or_insert_with(rows::RowLedger::default)
            .tighten(connection, debts)?;
        state.committing_bank = Some(committing_bank);
        install_schema_guard(
            connection,
            state
                .rows
                .as_ref()
                .is_some_and(rows::RowLedger::protects_schema),
        )
        .map_err(|error| error.to_string())
    }

    pub(crate) fn authorize_table_rows(
        &self,
        identity: &str,
        loans: &[rows::NativeTableRowLoan],
    ) -> Result<(), String> {
        if loans.is_empty() {
            return Ok(());
        }
        lock(&self.state)
            .rows
            .as_mut()
            .ok_or("native funded rows lack an owned transaction")?
            .authorize(identity, loans)
    }

    /// Restore the ordinary cap after a funded transaction ended.
    pub(crate) fn restore(&self, connection: &Connection) -> Result<(), String> {
        let cap = self.ordinary_cap(connection)?;
        self.apply(connection, cap)
    }

    /// A funded writer, before its writes, may add only `growth` pages: its
    /// own authenticated allowance. Every other owed growth stays reserved.
    pub(crate) fn authorize_funded_growth(
        &self,
        connection: &Connection,
        identity: &str,
        growth: u64,
    ) -> Result<(), String> {
        let pages = pragma_u64(connection, "page_count")?;
        let base = {
            let state = lock(&self.state);
            if state.priced.is_some() {
                return Err("ordinary current-write pricing cannot grant native growth".into());
            }
            if state.growth_grants.contains(identity) {
                return Ok(());
            }
            state.authorized.unwrap_or(pages)
        };
        let cap = base
            .checked_add(growth)
            .ok_or_else(|| "native authority funded cap exhausted".to_owned())?;
        self.apply(connection, cap)?;
        let mut state = lock(&self.state);
        state.authorized = Some(cap);
        state.growth_grants.insert(identity.into());
        Ok(())
    }

    /// An ordinary writer, before its first write, bounds its COMMIT by its
    /// priced current write instead of every page of the capped file. The
    /// price is checked here against this file's and every same-volume file's
    /// owed debt and the page budget, and stays applied, through any later
    /// gate entry, until the transaction commits or rolls back.
    pub(crate) fn authorize_current_write(
        &self,
        connection: &Connection,
        price: &AuthorityCurrentWritePrice,
    ) -> Result<(), String> {
        if connection.is_autocommit() {
            return Err("authority current-write price requires an owned transaction".to_owned());
        }
        {
            let state = lock(&self.state);
            if state.authorized.is_some() || state.priced.is_some() || state.funded.is_some() {
                return Err("authority transaction already has a write authorization".to_owned());
            }
        }
        let pages = pragma_u64(connection, "page_count")?;
        let cap = pages
            .checked_add(price.growth_pages())
            .ok_or_else(|| "native authority current-write cap exhausted".to_owned())?;
        let debt = native_authority_debt(connection, &self.store_uuid, self.device)
            .map_err(|error| error.to_string())?;
        if let Some(ceiling) = debt.pages.page_ceiling {
            if cap
                .checked_add(debt.pages.owed_pages)
                .is_none_or(|required| required > ceiling)
            {
                return Err("authority write would exceed an owed native page ceiling".to_owned());
            }
        }
        let available = main_database_available_bytes(connection)?;
        let wal = {
            let mut state = lock(&self.state);
            let observer = self.observer(&mut state)?;
            observed_wal_pressure(observer).map_err(|error| error.to_string())?
        };
        let current = SqlitePhysicalDebtAmountData::checked(price.wal_bytes(), price.disk_bytes())?;
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            wal,
            available,
            &debt.this_file,
            &debt.other_files,
            &current,
        )
        .map_err(|error| {
            #[cfg(feature = "admission-test-support")]
            eprintln!(
                "native current write refusal pending_wal={wal} owed_wal={} current_wal={} available_disk={available}",
                debt.this_file.wal_bytes(), current.wal_bytes(),
            );
            error
        })?;
        self.apply(connection, cap)?;
        let mut state = lock(&self.state);
        state.authorized = Some(cap);
        state.priced = Some((price.wal_bytes(), price.disk_bytes()));
        Ok(())
    }

    /// Record the priced amount an authenticated purpose spent in the open
    /// transaction; its COMMIT is checked against that amount alone.
    pub(crate) fn spend(&self, wal_bytes: u64, disk_bytes: u64) -> Result<(), String> {
        let mut state = lock(&self.state);
        if state.priced.is_some() {
            return Err(
                "ordinary authority writes cannot spend native finishing funding".to_owned(),
            );
        }
        let (wal, disk) = state.funded.unwrap_or((0, 0));
        state.funded = Some((
            wal.checked_add(wal_bytes)
                .ok_or_else(|| "native authority funded amount exhausted".to_owned())?,
            disk.checked_add(disk_bytes)
                .ok_or_else(|| "native authority funded amount exhausted".to_owned())?,
        ));
        Ok(())
    }

    /// The open transaction also carries unpriced writes: its COMMIT is
    /// ordinary intake, whatever account transition it made, under the
    /// ordinary cap restored before those writes.
    pub(crate) fn withdraw_funding(&self, connection: &Connection) -> Result<(), String> {
        {
            let mut state = lock(&self.state);
            state.funded = None;
            state.authorized = None;
            state.priced = None;
        }
        self.restore(connection)
    }

    /// Whether the last refused COMMIT was a capacity refusal. Taking it lets
    /// the owner report a known rollback instead of an unknown outcome.
    pub(crate) fn take_refusal(&self) -> bool {
        self.refused.swap(false, Ordering::AcqRel)
    }

    fn apply(&self, connection: &Connection, cap: u64) -> Result<(), String> {
        let cap = cap
            .min(self.initial_page_ceiling)
            .min(SQLITE_MAXIMUM_PAGE_COUNT);
        let value =
            i64::try_from(cap).map_err(|_| "native authority page cap is invalid".to_owned())?;
        connection
            .pragma_update(None, "max_page_count", value)
            .map_err(|error| error.to_string())?;
        lock(&self.state).cap = cap;
        Ok(())
    }

    /// The pages an ordinary transaction may reach: within the page budget,
    /// and with a frame for every page of the capped file plus its main-file
    /// growth inside the intake headroom of every owed debt.
    fn ordinary_cap(&self, connection: &Connection) -> Result<u64, String> {
        let pages = pragma_u64(connection, "page_count")?;
        let page_size = pragma_u64(connection, "page_size")?;
        let debt = native_authority_debt(connection, &self.store_uuid, self.device)
            .map_err(|error| error.to_string())?;
        // This gate preserves actual native lending. Once every loan on this
        // file and volume is released, restore the serving connection's
        // original limit; each ordinary owner retains its own intake policy.
        // Pricing the entire retained file here would turn historical bytes
        // into a permanent quota even though no native reserve is outstanding.
        if !has_outstanding_capacity(&debt) {
            return Ok(self.initial_page_ceiling);
        }
        let profile = crate::admission_operation_store::authority_current_write_profile(connection)
            .map_err(|error| error.to_string())?;
        let available = main_database_available_bytes(connection)?;
        let wal = {
            let mut state = lock(&self.state);
            state.writer_profile = Some(profile);
            let observer = self.observer(&mut state)?;
            observed_wal_pressure(observer).map_err(|error| error.to_string())?
        };
        // New pages alone bound the minimum physical cost of this possible
        // growth. Unchanged historical pages consume no new disk capacity.
        // No frame can spill: COMMIT separately prices all actual row/index
        // writes and refuses atomically if their complete cost does not fit.
        let fits = |growth: u64| -> bool {
            let current = (|| {
                let bound = committed_wal_bound(growth, page_size).ok()?;
                let disk = growth.checked_mul(page_size)?.checked_add(bound)?;
                SqlitePhysicalDebtAmountData::checked(bound, disk).ok()
            })();
            current.is_some_and(|current| {
                require_physical_write_capacity(
                    SqliteWriteCapacityStageData::Intake,
                    wal,
                    available,
                    &debt.this_file,
                    &debt.other_files,
                    &current,
                )
                .is_ok()
            })
        };
        let mut growth = 0_u64;
        if fits(0) {
            let mut high = available / page_size.max(1);
            while growth < high {
                let middle = growth + (high - growth).div_ceil(2);
                if fits(middle) {
                    growth = middle;
                } else {
                    high = middle - 1;
                }
            }
        }
        let disk_cap = pages.saturating_add(growth);
        Ok(match debt.pages.page_ceiling {
            Some(ceiling) => disk_cap.min(ceiling.saturating_sub(debt.pages.owed_pages)),
            None => disk_cap,
        })
    }

    /// The read-only observer of the same held authority file.
    fn observer<'a>(&self, state: &'a mut CapacityState) -> Result<&'a mut Connection, String> {
        if state.observer.is_none() {
            let observer = Connection::open_with_flags(
                &self.path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            )
            .map_err(|error| error.to_string())?;
            observer
                .busy_timeout(Duration::from_secs(5))
                .map_err(|error| error.to_string())?;
            let file = main_database_file_identity(&observer)?;
            if (file.device, file.inode) != (self.device, self.inode) {
                return Err("native authority file changed under its writer".to_owned());
            }
            state.observer = Some(observer);
        }
        state
            .observer
            .as_mut()
            .ok_or_else(|| "native authority observer is unavailable".to_owned())
    }

    fn permits_commit(
        &self,
        funded: Option<(u64, u64)>,
        priced: Option<(u64, u64)>,
        rows: Option<&rows::RowLedger>,
        committing_bank: Option<NativeAuthorityDebtData>,
    ) -> Result<(), String> {
        let mut state = lock(&self.state);
        let cap = state.cap;
        let writer_profile = state.writer_profile.clone();
        let observer = self.observer(&mut state)?;
        let available = main_database_available_bytes(observer)?;
        let wal = observed_wal_pressure(observer).map_err(|error| error.to_string())?;
        let tx = observer.transaction().map_err(|error| error.to_string())?;
        let pages = pragma_u64(&tx, "page_count")?;
        let debt = native_authority_debt(&tx, &self.store_uuid, self.device)
            .map_err(|error| error.to_string())?;
        if funded.is_none()
            && priced.is_none()
            && !has_outstanding_capacity(&debt)
            && committing_bank
                .as_ref()
                .is_none_or(|bank| !has_outstanding_capacity(bank))
        {
            return Ok(());
        }
        let (stage, owed, current) = match (funded, priced) {
            (Some((wal_bytes, disk_bytes)), _) => {
                let current = SqlitePhysicalDebtAmountData::checked(wal_bytes, disk_bytes)?;
                (
                    SqliteWriteCapacityStageData::OwedProgress,
                    debt.this_file.checked_sub(&current)?,
                    current,
                )
            }
            (None, Some((wal_bytes, disk_bytes))) => (
                SqliteWriteCapacityStageData::Intake,
                debt.this_file,
                SqlitePhysicalDebtAmountData::checked(wal_bytes, disk_bytes)?,
            ),
            (None, None) => {
                let shape = rows
                    .ok_or("ordinary authority transaction lost its row ledger")?
                    .current_write_shape(&tx)?;
                let (wal, disk) = match shape {
                    Some(shape) => {
                        let price = shape.price_without_spill(
                            writer_profile
                                .as_ref()
                                .ok_or("ordinary writer lost its authenticated frame profile")?,
                        )?;
                        (price.wal_bytes(), price.disk_bytes())
                    }
                    None => (0, 0),
                };
                (
                    SqliteWriteCapacityStageData::Intake,
                    debt.this_file,
                    SqlitePhysicalDebtAmountData::checked(wal, disk)?,
                )
            }
        };
        tx.commit().map_err(|error| error.to_string())?;
        require_physical_write_capacity(stage, wal, available, &owed, &debt.other_files, &current)
            .map_err(|error| format!("{error}: stage={stage:?} WAL={wal} owed={} current={} cap={cap} pages={pages} funded={funded:?} priced={priced:?}", owed.wal_bytes(), current.wal_bytes()))?;
        if let Some(bank) = committing_bank {
            // Its rows already contain the exact remaining purposes after
            // this writer's spends. Do not subtract the current write again.
            // Preserve both cuts: new reservations cannot hide behind the
            // observer's old bank, and releases cannot discount this commit.
            require_physical_write_capacity(
                stage,
                wal,
                available,
                &bank.this_file,
                &bank.other_files,
                &current,
            )?;
        }
        Ok(())
    }
}

/// A native bank with only settled history creates no physical loan. Neither
/// old nor newly published outstanding capacity may be skipped at COMMIT.
fn has_outstanding_capacity(debt: &NativeAuthorityDebtData) -> bool {
    debt.this_file.wal_bytes() != 0
        || debt.this_file.disk_bytes() != 0
        || debt.pages.owed_pages != 0
        || debt.pages.page_ceiling.is_some()
        || debt
            .other_files
            .iter()
            .any(|amount| amount.wal_bytes() != 0 || amount.disk_bytes() != 0)
}
