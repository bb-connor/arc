//! Native original finishing on the registered receipt sink.
//!
//! One guard per physical sink file holds the attached native bank and a
//! writer gate. Every pooled connection is checked out under the gate with
//! the bank's page cap applied through SQLite's own `max_page_count`, so no
//! direct writer can grow the file past the smallest owed page ceiling.
//! Receipt appends on the writer carry only the operator's cap and are
//! checked exactly before COMMIT instead, so the ceiling refuses them without
//! poisoning the verified head. New native debt is published only while the
//! gate is closed and no connection is checked out. Every commit preserves the
//! bank's disk debt on the file and its volume; ordinary writes are intake and
//! may be refused as backpressure, and only the prepaid receipt append handed
//! over by an authenticated native account spends its own purpose. Debt is
//! read through private read-only connections, never through the native
//! store's shared writer, so no receipt write waits on a native lock.
use super::bootstrap::receipt_write_schema::{
    quote_ordinary_receipt_batch, quote_receipt_append, OrdinaryReceiptAppendRequestData,
    ReceiptAppendQuoteData, ReceiptAppendRecipeData,
};
use super::support::extract_governed_transaction_metadata;
use super::*;
use crate::admission_operation_store::{
    native_receipt_is_owed, native_registered_file_debt, NativeRegisteredFileDebtData,
};
use chio_sqlite_file_identity::{
    main_database_available_bytes, main_database_file_identity, require_physical_write_capacity,
    SqliteConnectionIdentity, SqlitePhysicalDebtAmountData, SqliteWriteCapacityStageData,
};
use r2d2::PooledConnection;
use std::cell::{Cell, RefCell};
use std::ops::{Deref, DerefMut};
use std::sync::{Condvar, MutexGuard, PoisonError, Weak};

const SINK_PROFILE_SCHEMA: &str = "chio.native-finishing-receipt-sink-price.v3";
/// SQLite clamps a larger request to its compiled maximum page count.
const SQLITE_MAXIMUM_PAGE_COUNT: i64 = 4_294_967_294;
/// Publication and checkout never wait longer than this for the gate.
const GATE_WAIT: Duration = Duration::from_secs(30);

/// The one guard of each physical receipt sink file in this process.
static FILE_GUARDS: Mutex<Vec<FileGuard>> = Mutex::new(Vec::new());

struct FileGuard {
    device: u64,
    inode: u64,
    guard: Weak<NativeReceiptDebtGuard>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The authenticated native bank a receipt sink preserves from its open:
/// the authority file, path and serving owner of one native admission store.
/// Only that store mints it, from its own fenced read.
#[derive(Clone)]
pub struct NativeReceiptBankAttachment {
    view: NativeReceiptBankViewData,
    connection: Arc<crate::store_connection::StoreConnection>,
    owner: Arc<crate::serving_owner::SqliteServingOwner>,
}

impl NativeReceiptBankAttachment {
    pub(crate) fn new(
        view: NativeReceiptBankViewData,
        connection: Arc<crate::store_connection::StoreConnection>,
        owner: Arc<crate::serving_owner::SqliteServingOwner>,
    ) -> Self {
        Self {
            view,
            connection,
            owner,
        }
    }

    pub(super) fn view(&self) -> &NativeReceiptBankViewData {
        &self.view
    }

    /// Hold the actual serving writer across opening preflight and every
    /// opening commit. Publishing a loan for another file on this volume
    /// cannot race the receipt's switch from rollback journal to WAL.
    /// Retaining the owner also retains its filesystem serving lease: a stale
    /// attachment cannot serialize only an abandoned connection after reopen.
    pub(super) fn while_publication_is_held<T>(
        &self,
        open: impl FnOnce() -> Result<T, ReceiptStoreError>,
    ) -> Result<T, ReceiptStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        self.owner
            .verify_authority_anchor(&connection)
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        open()
    }
}

impl std::fmt::Debug for NativeReceiptBankAttachment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeReceiptBankAttachment")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}

/// The attached native authority file, its store identity and path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeReceiptBankViewData {
    pub(crate) native_path: String,
    pub(crate) native_device: u64,
    pub(crate) native_inode: u64,
    pub(crate) store_uuid: String,
}

/// Descriptive quote of one native receipt append on the actual sink file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeReceiptAppendQuote {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) wal_bytes: u64,
    pub(crate) disk_bytes: u64,
    pub(crate) wal_frames: u64,
    pub(crate) page_bucket: u64,
    pub(crate) page_growth: u64,
    pub(crate) fingerprint: String,
}

/// The ReceiptSink purpose an authenticated native account hands to this sink
/// for exactly one receipt: its envelope, registration and priced recipe.
pub(crate) struct NativeReceiptFundingData {
    pub(crate) receipt_bytes: u64,
    pub(crate) registration_digest: String,
    pub(crate) profile_digest: String,
    pub(crate) wal_bytes: u64,
    pub(crate) disk_bytes: u64,
    pub(crate) page_bucket: u64,
    pub(crate) page_growth: u64,
}

/// Shared by every store instance, pooled connection and writer thread of
/// one physical sink file.
pub(crate) struct NativeReceiptDebtGuard {
    bank: OnceLock<NativeReceiptBankViewData>,
    gate: Mutex<WriterGate>,
    gate_changed: Condvar,
    bank_reader: Mutex<Option<Connection>>,
}

#[derive(Default)]
struct WriterGate {
    holders: u64,
    publishing: bool,
    operator_page_cap: Option<i64>,
    native_page_cap: Option<u64>,
}

impl WriterGate {
    /// The operator's own configured cap, without the native page ceiling.
    fn operator_cap(&self) -> i64 {
        self.operator_page_cap.unwrap_or(SQLITE_MAXIMUM_PAGE_COUNT)
    }

    /// The page cap of a checkout: the operator's and the native ceiling's.
    fn page_cap(&self) -> i64 {
        let native = self
            .native_page_cap
            .map(|cap| i64::try_from(cap).unwrap_or(i64::MAX));
        [self.operator_page_cap, native]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(SQLITE_MAXIMUM_PAGE_COUNT)
    }
}

impl NativeReceiptDebtGuard {
    fn new(operator_page_cap: Option<i64>) -> Self {
        Self {
            bank: OnceLock::new(),
            gate: Mutex::new(WriterGate {
                operator_page_cap,
                ..WriterGate::default()
            }),
            gate_changed: Condvar::new(),
            bank_reader: Mutex::new(None),
        }
    }

    /// The process-wide guard of `connection`'s main file. A file without a
    /// verifiable identity gets a private guard and can never attach a bank.
    pub(super) fn for_file(connection: &Connection, operator_page_cap: Option<u32>) -> Arc<Self> {
        let operator = operator_page_cap.map(i64::from);
        let Ok(file) = main_database_file_identity(connection) else {
            return Arc::new(Self::new(operator));
        };
        let mut guards = lock(&FILE_GUARDS);
        guards.retain(|entry| entry.guard.strong_count() > 0);
        let existing = guards
            .iter()
            .find(|entry| (entry.device, entry.inode) == (file.device, file.inode))
            .and_then(|entry| entry.guard.upgrade());
        if let Some(guard) = existing {
            let mut gate = lock(&guard.gate);
            gate.operator_page_cap = match (gate.operator_page_cap, operator) {
                (Some(current), Some(requested)) => Some(current.min(requested)),
                (current, requested) => current.or(requested),
            };
            drop(gate);
            return guard;
        }
        let guard = Arc::new(Self::new(operator));
        guards.push(FileGuard {
            device: file.device,
            inode: file.inode,
            guard: Arc::downgrade(&guard),
        });
        guard
    }

    /// Attach the one native bank this file serves. Another bank refuses.
    pub(super) fn attach(&self, view: &NativeReceiptBankViewData) -> Result<(), ReceiptStoreError> {
        if self.bank.get_or_init(|| view.clone()) != view {
            return Err(ReceiptStoreError::Conflict(
                "receipt sink is attached to another native finishing bank".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn has_bank(&self) -> bool {
        self.bank.get().is_some()
    }

    /// An opening schema transaction's commit preserves the attached bank's
    /// debt and page budget. The complete pending page count is read on the
    /// owning transaction immediately before commit (spill is disabled before
    /// any mutation, so the commit writes each dirty page at most one frame),
    /// the price is checked on the owning connection, and the one-shot
    /// authorization is consumed by exactly this transaction's COMMIT. No
    /// read of the locked sink happens here; the bank is read through the
    /// shared private reader while publication is held.
    pub(super) fn require_open_commit(
        self: &Arc<Self>,
        connection: &Connection,
    ) -> Result<(), ReceiptStoreError> {
        OPENING_WRITE.with(|slot| slot.set(None));
        if !self.has_bank() {
            return Ok(());
        }
        let file = main_database_file_identity(connection).map_err(ReceiptStoreError::Conflict)?;
        let pending_pages = page_count(connection).map_err(ReceiptStoreError::Conflict)?;
        let page_size = receipt_page_size(connection).map_err(ReceiptStoreError::Conflict)?;
        let price = pending_pages
            .checked_mul(page_size + 24)
            .and_then(|bytes| bytes.checked_add(page_size + 56))
            .and_then(|wal| {
                let main_growth_bound = pending_pages.checked_mul(page_size)?;
                SqlitePhysicalDebtAmountData::checked(wal, wal.checked_add(main_growth_bound)?).ok()
            })
            .ok_or_else(|| {
                ReceiptStoreError::Conflict("receipt schema commit price exhausted".to_owned())
            })?;
        let committed_wal = connection
            .path()
            .map(|path| committed_wal_bytes(path))
            .transpose()
            .map_err(ReceiptStoreError::Conflict)?
            .unwrap_or(0);
        let available =
            main_database_available_bytes(connection).map_err(ReceiptStoreError::Conflict)?;
        let Some(bank) = self.bank.get().cloned() else {
            set_opening_write(file.device, file.inode, "receipt-schema-migration");
            return Ok(());
        };
        let mut reader = None;
        let native = open_bank_reader(&mut reader, &bank).map_err(ReceiptStoreError::Conflict)?;
        if let Some(debt) = registered_debt(native, &bank, file.device, file.inode)
            .map_err(ReceiptStoreError::Conflict)?
        {
            require_page_budget(&debt, pending_pages, 0).map_err(ReceiptStoreError::Conflict)?;
            require_physical_write_capacity(
                SqliteWriteCapacityStageData::Intake,
                committed_wal,
                available,
                &debt.this_file,
                &debt.other_files,
                &price,
            )
            .map_err(ReceiptStoreError::Conflict)?;
        }
        set_opening_write(file.device, file.inode, "receipt-schema-migration");
        Ok(())
    }

    fn registered(connection: &Connection) -> Option<Arc<Self>> {
        let file = main_database_file_identity(connection).ok()?;
        lock(&FILE_GUARDS)
            .iter()
            .find(|entry| (entry.device, entry.inode) == (file.device, file.inode))
            .and_then(|entry| entry.guard.upgrade())
    }

    /// Check one connection out: wait while debt is being published, count
    /// the holder and apply the current page cap before any statement runs.
    fn admit(
        self: &Arc<Self>,
        connection: &Connection,
    ) -> Result<ReceiptWriterTicket, ReceiptStoreError> {
        let gate = lock(&self.gate);
        let (mut gate, waited) = self
            .gate_changed
            .wait_timeout_while(gate, GATE_WAIT, |gate| gate.publishing)
            .unwrap_or_else(PoisonError::into_inner);
        if waited.timed_out() {
            return Err(ReceiptStoreError::Conflict(
                "receipt writer gate stayed closed".to_owned(),
            ));
        }
        let cap = gate.page_cap();
        gate.holders = gate.holders.checked_add(1).ok_or_else(|| {
            ReceiptStoreError::Conflict("receipt writer gate overflow".to_owned())
        })?;
        drop(gate);
        let ticket = ReceiptWriterTicket {
            guard: Arc::clone(self),
            connection: connection_identity(connection),
        };
        connection.pragma_update(None, "max_page_count", cap)?;
        bind_trusted_page_ceiling(connection)?;
        Ok(ticket)
    }

    /// Close the gate: one publisher at a time, and only once every checked
    /// out connection is back. The gate reopens when the token drops.
    fn close(&self) -> Result<ClosedGate<'_>, ReceiptStoreError> {
        let gate = lock(&self.gate);
        let (mut gate, waited) = self
            .gate_changed
            .wait_timeout_while(gate, GATE_WAIT, |gate| gate.publishing)
            .unwrap_or_else(PoisonError::into_inner);
        if waited.timed_out() {
            return Err(ReceiptStoreError::Conflict(
                "receipt writer gate is held by another publisher".to_owned(),
            ));
        }
        gate.publishing = true;
        let closed = ClosedGate { guard: self };
        let (gate, waited) = self
            .gate_changed
            .wait_timeout_while(gate, GATE_WAIT, |gate| gate.holders != 0)
            .unwrap_or_else(PoisonError::into_inner);
        drop(gate);
        if waited.timed_out() {
            return Err(ReceiptStoreError::Conflict(
                "receipt connections stayed checked out during native publication".to_owned(),
            ));
        }
        Ok(closed)
    }

    /// The attached bank's debt for one registered file, on the shared reader.
    fn read_debt(
        &self,
        bank: &NativeReceiptBankViewData,
        device: u64,
        inode: u64,
    ) -> Result<Option<NativeRegisteredFileDebtData>, ReceiptStoreError> {
        let mut reader = lock(&self.bank_reader);
        let native = open_bank_reader(&mut reader, bank).map_err(ReceiptStoreError::Conflict)?;
        registered_debt(native, bank, device, inode).map_err(ReceiptStoreError::Conflict)
    }

    fn receipt_is_owed(
        &self,
        bank: &NativeReceiptBankViewData,
        receipt_id: &str,
    ) -> Result<bool, ReceiptStoreError> {
        let mut reader = lock(&self.bank_reader);
        let native = open_bank_reader(&mut reader, bank).map_err(ReceiptStoreError::Conflict)?;
        let tx = native.transaction()?;
        let owed = native_receipt_is_owed(&tx, receipt_id)
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        tx.commit()?;
        Ok(owed)
    }
}

/// A checked-out connection's hold on its file's writer gate.
pub(crate) struct ReceiptWriterTicket {
    guard: Arc<NativeReceiptDebtGuard>,
    connection: SqliteConnectionIdentity,
}

impl Drop for ReceiptWriterTicket {
    fn drop(&mut self) {
        TRUSTED_PAGE_CEILING.with(|slot| {
            if slot
                .get()
                .is_some_and(|bound| bound.connection == self.connection)
            {
                slot.set(None);
            }
        });
        clear_ordinary_connection(self.connection);
        let mut gate = lock(&self.guard.gate);
        gate.holders = gate.holders.saturating_sub(1);
        drop(gate);
        self.guard.gate_changed.notify_all();
    }
}

struct ClosedGate<'a> {
    guard: &'a NativeReceiptDebtGuard,
}

impl ClosedGate<'_> {
    fn set_native_page_cap(&self, debt: Option<&NativeRegisteredFileDebtData>) {
        lock(&self.guard.gate).native_page_cap = debt.and_then(|debt| {
            debt.page_ceiling
                .map(|ceiling| ceiling.saturating_sub(debt.owed_pages))
        });
    }
}

impl Drop for ClosedGate<'_> {
    fn drop(&mut self) {
        lock(&self.guard.gate).publishing = false;
        self.guard.gate_changed.notify_all();
    }
}

/// A pooled receipt connection checked out under its file's writer gate,
/// with the native page cap applied before any statement runs.
pub(crate) struct SqliteStoreConnection {
    connection: PooledConnection<SqliteConnectionManager>,
    _ticket: Option<ReceiptWriterTicket>,
}

impl Deref for SqliteStoreConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

impl DerefMut for SqliteStoreConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }
}

/// Admit one pooled connection to its file's gate. A file without a
/// registered guard is not a sink any native bank can attach to.
pub(crate) fn gate_connection(
    connection: PooledConnection<SqliteConnectionManager>,
) -> Result<SqliteStoreConnection, ReceiptStoreError> {
    let ticket = match NativeReceiptDebtGuard::registered(&connection) {
        Some(guard) => Some(guard.admit(&connection)?),
        None => None,
    };
    Ok(SqliteStoreConnection {
        connection,
        _ticket: ticket,
    })
}

fn open_bank_reader<'a>(
    reader: &'a mut Option<Connection>,
    bank: &NativeReceiptBankViewData,
) -> Result<&'a mut Connection, String> {
    if reader.is_none() {
        let native = open_read_only(&bank.native_path, Duration::from_secs(5))?;
        let identity = main_database_file_identity(&native)?;
        if (identity.device, identity.inode) != (bank.native_device, bank.native_inode) {
            return Err("native finishing bank file changed".to_owned());
        }
        *reader = Some(native);
    }
    reader
        .as_mut()
        .ok_or_else(|| "native finishing bank reader is unavailable".to_owned())
}

/// The prepaid amount and page growth a funded receipt COMMIT spends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FundedCommit {
    wal_bytes: u64,
    disk_bytes: u64,
    page_growth: u64,
}

#[derive(Clone, Copy)]
struct OrdinaryCommit {
    connection: SqliteConnectionIdentity,
    price: FundedCommit,
}

#[derive(Clone, Copy)]
struct TrustedPageCeiling {
    connection: SqliteConnectionIdentity,
    pages: u64,
}

fn connection_identity(connection: &Connection) -> SqliteConnectionIdentity {
    SqliteConnectionIdentity::of(connection)
}

fn ordinary_price(connection: SqliteConnectionIdentity, consume: bool) -> Option<FundedCommit> {
    ORDINARY_COMMIT.with(|slot| {
        let token = slot.get().filter(|token| token.connection == connection)?;
        if consume {
            slot.set(None);
        }
        Some(token.price)
    })
}

fn clear_ordinary_connection(connection: SqliteConnectionIdentity) {
    ORDINARY_COMMIT.with(|slot| {
        if slot
            .get()
            .is_some_and(|token| token.connection == connection)
        {
            slot.set(None);
        }
    });
}

thread_local! {
    /// The funded receipt transaction this thread is about to commit.
    /// COMMIT consumes it and ROLLBACK discards it.
    static FUNDED_COMMIT: Cell<Option<FundedCommit>> = const { Cell::new(None) };
    /// The ordinary receipt transaction this thread priced exactly before
    /// mutation: the batch's summed authenticated quote. COMMIT consumes it
    /// at Intake (no own-loan subtraction) and ROLLBACK discards it.
    static ORDINARY_COMMIT: Cell<Option<OrdinaryCommit>> = const { Cell::new(None) };
    /// The actual enforced `max_page_count` ceiling of the pooled connection
    /// this thread most recently checked out, read back from that connection
    /// after its cap was applied and before any mutation. This is the
    /// per-connection hard bound the SAFE fallback prices by; a thread that
    /// never checked out a connection has none, and its unpriced commits
    /// refuse.
    static TRUSTED_PAGE_CEILING: Cell<Option<TrustedPageCeiling>> = const { Cell::new(None) };
    /// The writer connection's cache-spill setting to restore after a funded
    /// transaction ends.
    static SPILL_RESTORE: Cell<Option<bool>> = const { Cell::new(None) };
    /// The receipt writer thread's guard and its cached read-only observers.
    static WRITER_DEBT: RefCell<Option<DebtObservers>> = const { RefCell::new(None) };
    /// Why the debt hook last refused a COMMIT on this thread. SQLite reports
    /// only a bare constraint failure for a refusing commit hook.
    static COMMIT_REFUSAL: RefCell<Option<String>> = const { RefCell::new(None) };
    /// The opening thread's one-shot write authorizations and its current
    /// stage. An authorization is bound to one actual connection and file,
    /// priced and checked before its single statement or transaction runs,
    /// and consumed by exactly one COMMIT of that connection; a commit
    /// during the open without one refuses with its stage.
    static OPENING_WRITE: Cell<Option<OpeningWrite>> = const { Cell::new(None) };
    static OPENING_STAGE: Cell<Option<OpeningStage>> = const { Cell::new(None) };
}

/// One priced, checked authorization for exactly one commit of one opening
/// connection. The price was charged at authorization time on the owning
/// connection; the hook only matches identity and consumes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpeningWrite {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) stage: &'static str,
}

/// The opening stage of one actual sink file: a commit of that file during
/// the open without an explicit authorization refuses with the exact
/// operation stage and identity. A commit of any other file, connection or
/// store is never rejected by it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpeningStage {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) stage: &'static str,
}

/// Marks the thread as opening one receipt sink. Dropping it clears the
/// stage and any unconsumed authorization on every path, so no later
/// unrelated commit can ever spend one.
pub(crate) struct OpeningStageGuard {
    _private: (),
}

impl Drop for OpeningStageGuard {
    fn drop(&mut self) {
        clear_opening_wal_switch();
        OPENING_STAGE.with(|slot| slot.set(None));
    }
}

/// Begin the opening stage of the sink file of `connection`. A connection
/// without a verifiable file identity opens no stage. Every commit of that
/// file during the open must hold an explicit one-shot authorization; one
/// that does not refuses with the exact stage and identity.
pub(super) fn begin_receipt_sink_open(connection: &Connection) -> Option<OpeningStageGuard> {
    let file = main_database_file_identity(connection).ok()?;
    OPENING_STAGE.with(|slot| {
        slot.set(Some(OpeningStage {
            device: file.device,
            inode: file.inode,
            stage: "receipt-sink-open",
        }))
    });
    Some(OpeningStageGuard { _private: () })
}

fn set_opening_write(device: u64, inode: u64, stage: &'static str) {
    OPENING_WRITE.with(|slot| {
        slot.set(Some(OpeningWrite {
            device,
            inode,
            stage,
        }))
    });
    OPENING_STAGE.with(|slot| {
        slot.set(Some(OpeningStage {
            device,
            inode,
            stage,
        }))
    });
}

/// Bytes the switch to WAL writes in rollback-journal mode: page one, and a
/// journal of one sector-padded header and page one's prior image.
fn opening_switch_disk_bytes(page_size: u64) -> Result<u64, String> {
    page_size
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(65_536 + 8))
        .ok_or_else(|| "native receipt opening switch size exhausted".to_owned())
}

/// Check on the opening connection, before its file switches to WAL, that the
/// switch preserves the attached bank's debt and page budget. The switch's
/// COMMIT then spends exactly this check; a file already in WAL owes none.
pub(super) fn authorize_opening_wal_switch(
    connection: &Connection,
    guard: &Arc<NativeReceiptDebtGuard>,
) -> Result<(), ReceiptStoreError> {
    OPENING_WRITE.with(|slot| slot.set(None));
    let Some(bank) = guard.bank.get().cloned() else {
        return Ok(());
    };
    let mode: String = connection.query_row("PRAGMA main.journal_mode", [], |row| row.get(0))?;
    match mode.as_str() {
        "wal" => return Ok(()),
        "delete" => {}
        other => {
            return Err(ReceiptStoreError::Conflict(format!(
                "native receipt sink journal mode {other} is unsupported"
            )))
        }
    }
    let file = main_database_file_identity(connection).map_err(ReceiptStoreError::Conflict)?;
    let pages = page_count(connection).map_err(ReceiptStoreError::Conflict)?;
    let page_size: i64 = connection.query_row("PRAGMA main.page_size", [], |row| row.get(0))?;
    let page_size = u64::try_from(page_size)
        .map_err(|_| ReceiptStoreError::Conflict("receipt page size is invalid".to_owned()))?;
    let available =
        main_database_available_bytes(connection).map_err(ReceiptStoreError::Conflict)?;
    let mut reader = None;
    let native = open_bank_reader(&mut reader, &bank).map_err(ReceiptStoreError::Conflict)?;
    if let Some(debt) = registered_debt(native, &bank, file.device, file.inode)
        .map_err(ReceiptStoreError::Conflict)?
    {
        let checked = require_page_budget(&debt, pages.max(1), 0).and_then(|()| {
            require_physical_write_capacity(
                SqliteWriteCapacityStageData::Intake,
                0,
                available,
                &debt.this_file,
                &debt.other_files,
                &SqlitePhysicalDebtAmountData::checked(0, opening_switch_disk_bytes(page_size)?)?,
            )
        });
        checked.map_err(ReceiptStoreError::Conflict)?;
    }
    OPENING_WRITE.with(|slot| slot.set(None));
    set_opening_write(file.device, file.inode, "journal-mode-wal-switch");
    Ok(())
}

/// Authorize the auto-vacuum header statement of the open: one identified
/// statement whose physical write, when the file has a header at all, is one
/// page rewrite, one WAL frame plus the WAL header and one padding frame. An
/// empty database writes nothing and leaves the authorization unconsumed.
pub(super) fn authorize_opening_header_write(
    connection: &Connection,
    guard: &Arc<NativeReceiptDebtGuard>,
    stage: &'static str,
) -> Result<(), ReceiptStoreError> {
    OPENING_WRITE.with(|slot| slot.set(None));
    let Some(bank) = guard.bank.get().cloned() else {
        return Ok(());
    };
    let file = main_database_file_identity(connection).map_err(ReceiptStoreError::Conflict)?;
    let page_size = receipt_page_size(connection).map_err(ReceiptStoreError::Conflict)?;
    // One header frame, one FULL-sync padding frame, and the WAL header.
    // A fresh header can also add one main-file page at checkpoint.
    let wal_price = page_size
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(80))
        .ok_or_else(|| ReceiptStoreError::Conflict("receipt header price exhausted".to_owned()))?;
    let disk_price = wal_price.checked_add(page_size).ok_or_else(|| {
        ReceiptStoreError::Conflict("receipt header disk price exhausted".to_owned())
    })?;
    let mode: String = connection.query_row("PRAGMA main.journal_mode", [], |row| row.get(0))?;
    let price = match mode.as_str() {
        "wal" => SqlitePhysicalDebtAmountData::checked(wal_price, disk_price),
        // Application-id adoption precedes the switch to WAL. Preserve the
        // rollback journal's sector/header and original page, plus the main
        // header page, instead of pricing this as a WAL append.
        "delete" => SqlitePhysicalDebtAmountData::checked(
            0,
            opening_switch_disk_bytes(page_size).map_err(ReceiptStoreError::Conflict)?,
        ),
        _ => {
            return Err(ReceiptStoreError::Conflict(format!(
                "unsupported receipt opening journal mode {mode}"
            )))
        }
    }
    .map_err(ReceiptStoreError::Conflict)?;
    let committed_wal = connection
        .path()
        .map(|path| committed_wal_bytes(path))
        .transpose()
        .map_err(ReceiptStoreError::Conflict)?
        .unwrap_or(0);
    let available =
        main_database_available_bytes(connection).map_err(ReceiptStoreError::Conflict)?;
    let mut reader = None;
    let native = open_bank_reader(&mut reader, &bank).map_err(ReceiptStoreError::Conflict)?;
    if let Some(debt) = registered_debt(native, &bank, file.device, file.inode)
        .map_err(ReceiptStoreError::Conflict)?
    {
        let pages = page_count(connection).map_err(ReceiptStoreError::Conflict)?;
        require_page_budget(&debt, pages.max(1), 0).map_err(ReceiptStoreError::Conflict)?;
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            committed_wal,
            available,
            &debt.this_file,
            &debt.other_files,
            &price,
        )
        .map_err(ReceiptStoreError::Conflict)?;
    }
    set_opening_write(file.device, file.inode, stage);
    Ok(())
}

/// Committed WAL bytes of the sink, from the file size. An absent WAL is
/// exactly zero bytes; any other read error refuses instead of guessing.
fn committed_wal_bytes(path: &str) -> Result<u64, String> {
    match std::fs::metadata(format!("{path}-wal")) {
        Ok(data) => Ok(data.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.to_string()),
    }
}

/// Discard an opening authorization its commit did not spend.
pub(super) fn clear_opening_wal_switch() {
    OPENING_WRITE.with(|slot| slot.set(None));
}

struct DebtObservers {
    guard: Arc<NativeReceiptDebtGuard>,
    installed: Option<(u64, u64)>,
    receipt: Option<Connection>,
    native: Option<Connection>,
}

impl DebtObservers {
    fn new(guard: &Arc<NativeReceiptDebtGuard>, installed: Option<(u64, u64)>) -> Self {
        Self {
            guard: Arc::clone(guard),
            installed,
            receipt: None,
            native: None,
        }
    }

    fn receipt_observer(&mut self, path: &str) -> Result<&Connection, String> {
        if self.receipt.is_none() {
            self.receipt = Some(open_read_only(path, Duration::ZERO)?);
        }
        self.receipt
            .as_ref()
            .ok_or_else(|| "native receipt observer is unavailable".to_owned())
    }

    fn native_reader(
        &mut self,
        bank: &NativeReceiptBankViewData,
    ) -> Result<&mut Connection, String> {
        open_bank_reader(&mut self.native, bank)
    }

    /// Whether committing on the receipt file at `path` preserves the attached
    /// bank's debt and page budget. `pending_pages` is the page count of the
    /// transaction about to commit when its writer can read it; `funded` is
    /// the prepaid recipe the commit spends, if any; `ordinary` is the exact
    /// quote of the current ordinary receipt transaction, if it priced one.
    fn permits(
        &mut self,
        path: Option<&str>,
        pending_pages: Option<u64>,
        funded: Option<FundedCommit>,
        ordinary: Option<FundedCommit>,
        connection: SqliteConnectionIdentity,
    ) -> Result<(), String> {
        let Some(bank) = self.guard.bank.get().cloned() else {
            return match funded {
                None => Ok(()),
                Some(_) => Err("native receipt append has no attached finishing bank".to_owned()),
            };
        };
        let path =
            path.ok_or_else(|| "native receipt sink requires a persistent file".to_owned())?;
        let installed = self.installed;
        let receipt = self.receipt_observer(path)?;
        let file = main_database_file_identity(receipt)?;
        if installed.is_some_and(|installed| installed != (file.device, file.inode)) {
            return Err("native receipt sink file changed under its writer".to_owned());
        }
        // Reading the file first refreshes the observer's journal mode.
        let committed_pages = page_count(receipt)?;
        let pending_wal = receipt_wal_pressure(receipt)?;
        let available = main_database_available_bytes(receipt)?;
        let page_size = receipt_page_size(receipt)?;
        let native = self.native_reader(&bank)?;
        let Some(debt) = registered_debt(native, &bank, file.device, file.inode)? else {
            return match funded {
                None => Ok(()),
                Some(_) => Err("native receipt append has no outstanding bank debt".to_owned()),
            };
        };
        require_page_budget(
            &debt,
            pending_pages.unwrap_or(committed_pages),
            funded.map_or(0, |funded| funded.page_growth),
        )?;
        let (stage, owed, current) = match funded {
            None => {
                // An ordinary commit is Intake: it may be refused as
                // backpressure but never spends a native loan. Its current
                // write is priced exactly when its writer quoted it
                // (`ordinary`), otherwise by the SAFE fallback: a transaction
                // on a managed connection (cache spill off before mutation)
                // can dirty at most its enforced `max_page_count` pages, each
                // at most once at COMMIT plus FULL-sync padding, and grow the
                // main file by at most that same cap. Only a trusted checked
                // out ceiling counts; a soft or absent one refuses.
                let priced = match ordinary {
                    Some(ordinary) => SqlitePhysicalDebtAmountData::checked(
                        ordinary.wal_bytes,
                        ordinary.disk_bytes,
                    )?,
                    None => {
                        // The SAFE fallback price: the trusted enforced
                        // ceiling of the pooled connection this thread
                        // checked out, read back from that connection after
                        // its cap was applied and bound before any mutation.
                        // The writer's post-lift ceiling is its operator cap;
                        // a lifted connection never claims the gate's lower
                        // native ceiling. No bound: refuse as backpressure.
                        let ceiling = TRUSTED_PAGE_CEILING
                            .with(Cell::get)
                            .filter(|bound| bound.connection == connection)
                            .map(|bound| bound.pages)
                            .ok_or_else(|| {
                                "ordinary receipt write has no trusted page ceiling".to_owned()
                            })?;
                        let wal = ceiling
                            .checked_mul(page_size + 24)
                            .and_then(|bytes| bytes.checked_add(page_size + 56))
                            .ok_or_else(|| "ordinary receipt ceiling price exhausted".to_owned())?;
                        let disk = wal
                            .checked_add(ceiling.checked_mul(page_size).ok_or_else(|| {
                                "ordinary receipt ceiling price exhausted".to_owned()
                            })?)
                            .ok_or_else(|| "ordinary receipt ceiling price exhausted".to_owned())?;
                        SqlitePhysicalDebtAmountData::checked(wal, disk)?
                    }
                };
                (SqliteWriteCapacityStageData::Intake, debt.this_file, priced)
            }
            Some(funded) => {
                let current =
                    SqlitePhysicalDebtAmountData::checked(funded.wal_bytes, funded.disk_bytes)?;
                (
                    SqliteWriteCapacityStageData::OwedProgress,
                    debt.this_file.checked_sub(&current)?,
                    current,
                )
            }
        };
        require_physical_write_capacity(
            stage,
            pending_wal,
            available,
            &owed,
            &debt.other_files,
            &current,
        )
    }
}

/// The page count plus every owed loan's growth stays within the smallest
/// owed ceiling. A funded commit's own growth is already in its page count.
fn require_page_budget(
    debt: &NativeRegisteredFileDebtData,
    pages: u64,
    realized_growth: u64,
) -> Result<(), String> {
    let Some(ceiling) = debt.page_ceiling else {
        return Ok(());
    };
    let owed = debt
        .owed_pages
        .checked_sub(realized_growth)
        .ok_or_else(|| "native receipt page budget lost its own loan".to_owned())?;
    if pages
        .checked_add(owed)
        .is_none_or(|required| required > ceiling)
    {
        return Err("receipt write would exceed an owed native page ceiling".to_owned());
    }
    Ok(())
}

/// Committed WAL pressure of the receipt file. A file still in rollback
/// journal mode has no WAL frames; only its own switch to WAL commits there.
fn receipt_wal_pressure(receipt: &Connection) -> Result<u64, String> {
    let mode: String = receipt
        .query_row("PRAGMA main.journal_mode", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    match mode.as_str() {
        "wal" => crate::admission_operation_store::observed_wal_pressure(receipt)
            .map_err(|error| error.to_string()),
        "delete" => Ok(0),
        other => Err(format!(
            "native receipt sink journal mode {other} is unsupported"
        )),
    }
}

fn page_count(connection: &Connection) -> Result<u64, String> {
    let pages: i64 = connection
        .query_row("PRAGMA main.page_count", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    u64::try_from(pages).map_err(|_| "receipt page count is invalid".to_owned())
}

fn receipt_page_size(connection: &Connection) -> Result<u64, String> {
    let size: i64 = connection
        .query_row("PRAGMA main.page_size", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    u64::try_from(size).map_err(|_| "receipt page size is invalid".to_owned())
}

fn open_read_only(path: &str, busy: Duration) -> Result<Connection, String> {
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|error| error.to_string())?;
    connection
        .busy_timeout(busy)
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

/// The attached bank's debt for `(device, inode)` in one read transaction.
fn registered_debt(
    native: &mut Connection,
    bank: &NativeReceiptBankViewData,
    device: u64,
    inode: u64,
) -> Result<Option<NativeRegisteredFileDebtData>, String> {
    let tx = native.transaction().map_err(|error| error.to_string())?;
    let debt = native_registered_file_debt(&tx, &bank.store_uuid, device, inode)
        .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(debt)
}

/// Every pooled receipt connection refuses a COMMIT that would borrow the
/// attached bank's debt or page budget. The writer thread refuses earlier,
/// before COMMIT and with its exact pending page count, so a refusal there
/// never poisons the verified head; this is the backstop for every writer.
pub(super) fn install_native_receipt_debt_hooks(
    connection: &Connection,
    guard: &Arc<NativeReceiptDebtGuard>,
) -> rusqlite::Result<()> {
    let installed = main_database_file_identity(connection)
        .ok()
        .map(|identity| (identity.device, identity.inode));
    let path = connection.path().map(str::to_owned);
    let mut observers = DebtObservers::new(guard, installed);
    let writer = connection_identity(connection);
    connection.commit_hook(Some(move || {
        let funded = FUNDED_COMMIT.with(Cell::take);
        if let Some(write) = OPENING_WRITE.with(Cell::take) {
            if funded.is_none() && installed == Some((write.device, write.inode)) {
                // Consume exactly this connection's one authorized commit.
                return false;
            }
            COMMIT_REFUSAL.with(|slot| {
                *slot.borrow_mut() = Some(format!(
                    "native receipt opening authorization for stage {} was consumed by another commit",
                    write.stage
                ))
            });
            return true;
        }
        if let Some(stage) = OPENING_STAGE.with(Cell::get) {
            // Only the staged sink file's own commits refuse here; another
            // file's or store's commit is not this open's business.
            if installed == Some((stage.device, stage.inode)) {
                COMMIT_REFUSAL.with(|slot| {
                    *slot.borrow_mut() = Some(format!(
                        "a commit of receipt sink device {} inode {} path {} reached opening stage {} without an explicit authorization",
                        stage.device,
                        stage.inode,
                        path.as_deref().unwrap_or("<unidentified>"),
                        stage.stage
                    ))
                });
                return true;
            }
        }
        match observers.permits(
            path.as_deref(),
            None,
            funded,
            // COMMIT consumes the ordinary token: it is spent exactly once,
            // by this commit of this connection, and a later commit never
            // re-spends it. ROLLBACK discards it.
            ordinary_price(writer, true),
            writer,
        ) {
            Ok(()) => false,
            Err(reason) => {
                COMMIT_REFUSAL.with(|slot| *slot.borrow_mut() = Some(reason));
                true
            }
        }
    }))?;
    connection.rollback_hook(Some(move || {
        FUNDED_COMMIT.with(|funded| funded.set(None));
        clear_ordinary_connection(writer);
    }))
}

/// Run an open whose commits the debt hook checks on this thread, reporting a
/// refused COMMIT by the hook's own reason.
pub(super) fn with_commit_refusal<T>(
    open: impl FnOnce() -> Result<T, ReceiptStoreError>,
) -> Result<T, ReceiptStoreError> {
    COMMIT_REFUSAL.with(|slot| slot.borrow_mut().take());
    let opened = open();
    let refusal = COMMIT_REFUSAL.with(|slot| slot.borrow_mut().take());
    match (opened, refusal) {
        (Err(_), Some(reason)) => Err(ReceiptStoreError::Conflict(format!(
            "native receipt commit refused: {reason}"
        ))),
        (opened, _) => opened,
    }
}

/// Bind the supervised writer thread to its sink's guard.
pub(super) fn enter_receipt_writer(guard: &Arc<NativeReceiptDebtGuard>) {
    WRITER_DEBT.with(|slot| *slot.borrow_mut() = Some(DebtObservers::new(guard, None)));
}

/// The writer thread checks its pending transaction before COMMIT: ordinary
/// writes as intake, a funded receipt append against its own purpose.
pub(super) fn require_receipt_commit(connection: &Connection) -> Result<(), ReceiptStoreError> {
    let funded = FUNDED_COMMIT.with(Cell::get);
    let pending_pages = page_count(connection).map_err(ReceiptStoreError::Conflict)?;
    WRITER_DEBT.with(|slot| match slot.borrow_mut().as_mut() {
        Some(observers) => observers
            .permits(
                connection.path(),
                Some(pending_pages),
                funded,
                ordinary_price(connection_identity(connection), false),
                connection_identity(connection),
            )
            .map_err(ReceiptStoreError::Conflict),
        None => Ok(()),
    })
}

/// Price the complete ordinary receipt batch exactly through the
/// authenticated receipt write schema before its first mutation, and bind
/// the summed Intake price to this thread's actual transaction connection
/// as a one-shot token: COMMIT consumes it, ROLLBACK discards it. Ordinary
/// is Intake: no native funding and no own-loan subtraction. Every request
/// of the batch is priced, including existing-lineage refreshes, coalesced
/// intra-batch edges, duplicate receipt ids and requests without a
/// capability lineage row; a quote that fails refuses the batch closed. The
/// whole-file SAFE ceiling fallback stays reserved for genuinely unpriced
/// non-append writers.
pub(super) fn authorize_ordinary_receipt_batch(
    tx: &rusqlite::Transaction<'_>,
    requests: &[super::ReceiptCommitRequest],
    anchored: bool,
) -> Result<(), ReceiptStoreError> {
    ORDINARY_COMMIT.with(|slot| slot.set(None));
    if requests.is_empty() {
        return Ok(());
    }
    let views = requests
        .iter()
        .map(|request| {
            let governed = extract_governed_transaction_metadata(&request.receipt);
            let call_chain = governed
                .as_ref()
                .and_then(|governed| governed.call_chain.as_ref());
            Ok::<_, ReceiptStoreError>(OrdinaryReceiptAppendRequestData {
                receipt_bytes: u64::try_from(request.raw_json.len()).map_err(|_| {
                    ReceiptStoreError::Conflict("receipt envelope size is invalid".to_owned())
                })?,
                receipt_id: request.receipt.id.as_str(),
                capability_id: request.receipt.capability_id.as_str(),
                ensure_lineage: request.ensure_lineage,
                creates_governed_lineage_row: call_chain.is_some(),
                governed_parent_receipt_id: call_chain
                    .and_then(|chain| chain.parent_receipt_id.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let quote = quote_ordinary_receipt_batch(tx, &views, anchored)?;
    ORDINARY_COMMIT.with(|slot| {
        slot.set(Some(OrdinaryCommit {
            connection: connection_identity(tx),
            price: FundedCommit {
                wal_bytes: quote.wal_bytes(),
                disk_bytes: quote.disk_bytes(),
                page_growth: quote.maximum_page_growth(),
            },
        }))
    });
    Ok(())
}

/// Discard an ordinary batch token its commit did not spend.
pub(super) fn clear_ordinary_commit() {
    ORDINARY_COMMIT.with(|slot| slot.set(None));
}

/// Bind this thread's actual enforced page ceiling for the next ordinary
/// commit's fallback price. The value is read back from `connection`'s own
/// `PRAGMA main.max_page_count`: the effective ceiling SQLite enforces on
/// that connection, after any cap this checkout applied, never a requested
/// or remembered value. It is bound after the cap is applied and before any
/// mutation, so it is installed, enforced and stable through the
/// transaction; the commit hook prices by it without reentering SQLite.
pub(super) fn bind_trusted_page_ceiling(connection: &Connection) -> Result<(), ReceiptStoreError> {
    TRUSTED_PAGE_CEILING.with(|slot| slot.set(None));
    let spill: i64 = connection.query_row("PRAGMA main.cache_spill", [], |row| row.get(0))?;
    if spill != 0 {
        return Err(ReceiptStoreError::Conflict(
            "ordinary receipt price requires cache spill disabled".to_owned(),
        ));
    }
    let effective: i64 =
        connection.query_row("PRAGMA main.max_page_count", [], |row| row.get(0))?;
    let ceiling = u64::try_from(effective)
        .map_err(|_| ReceiptStoreError::Conflict("receipt page ceiling is invalid".to_owned()))?;
    if ceiling == 0 {
        return Err(ReceiptStoreError::Conflict(
            "receipt page ceiling is unusable".to_owned(),
        ));
    }
    TRUSTED_PAGE_CEILING.with(|slot| {
        slot.set(Some(TrustedPageCeiling {
            connection: connection_identity(connection),
            pages: ceiling,
        }))
    });
    Ok(())
}

/// A receipt append on the writer is checked exactly before COMMIT with its
/// pending page count and refused there without poisoning the verified head.
/// Its connection therefore carries only the operator's cap, so the native
/// ceiling never surfaces as a store-wide SQLITE_FULL inside the append.
pub(super) fn lift_native_page_cap(connection: &Connection) -> Result<(), ReceiptStoreError> {
    if let Some(guard) = NativeReceiptDebtGuard::registered(connection) {
        let cap = lock(&guard.gate).operator_cap();
        connection.pragma_update(None, "max_page_count", cap)?;
        // The lifted connection's enforced ceiling is its operator cap (or
        // SQLite's own when none): rebind the trusted per-connection ceiling
        // after the lift, so this connection never claims the lower native
        // ceiling the gate still carries for other connections.
        bind_trusted_page_ceiling(connection)?;
    }
    Ok(())
}

/// Restore the writer connection's cache profile after a funded transaction
/// ended, committed or rolled back.
pub(super) fn restore_writer_profile(connection: &Connection) -> Result<(), ReceiptStoreError> {
    match SPILL_RESTORE.with(Cell::take) {
        Some(true) => connection.execute_batch("PRAGMA cache_spill = ON")?,
        Some(false) | None => (),
    }
    Ok(())
}

/// No lineage statement may name a native receipt whose prepaid append is
/// still owed. The funded append is priced with no lineage refresh, and this
/// holds that price on every writer until the append commits.
pub(super) fn require_lineage_names_no_owed_receipt(
    tx: &Connection,
    receipt_id: &str,
    parent_receipt_id: Option<&str>,
) -> Result<(), ReceiptStoreError> {
    // Every writer of a sink file finds the same guard through the file; a
    // file without one is not a sink any native bank can attach to.
    let Some(guard) = NativeReceiptDebtGuard::registered(tx) else {
        return Ok(());
    };
    let Some(bank) = guard.bank.get() else {
        return Ok(());
    };
    for id in std::iter::once(receipt_id).chain(parent_receipt_id) {
        let retained: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_tool_receipts WHERE receipt_id = ?1)",
            [id],
            |row| row.get(0),
        )?;
        if retained {
            continue;
        }
        if guard.receipt_is_owed(bank, id)? {
            return Err(ReceiptStoreError::Conflict(format!(
                "receipt lineage cannot name native receipt {id} before its funded append"
            )));
        }
    }
    Ok(())
}

/// The price profile of one ReceiptSink purpose: the registered sink, the
/// exact catalog fingerprint, the envelope, the capability whose lineage keys
/// the producer copies, the quoted amounts and the page recipe.
pub(crate) fn native_receipt_sink_profile(
    quote: &NativeReceiptAppendQuote,
    registration_digest: &str,
    receipt_bytes: u64,
    capability_id: &str,
) -> Result<String, ReceiptStoreError> {
    let bytes = canonical_json_bytes(&(
        SINK_PROFILE_SCHEMA,
        registration_digest,
        &quote.fingerprint,
        receipt_bytes,
        capability_id,
        (quote.wal_bytes, quote.disk_bytes),
        (quote.page_bucket, quote.page_growth),
    ))
    .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn native_quote(
    connection: &Connection,
    receipt_bytes: u64,
    capability_id: &str,
    minimum_page_bucket: u64,
    anchored: bool,
) -> Result<NativeReceiptAppendQuote, ReceiptStoreError> {
    let file = main_database_file_identity(connection).map_err(ReceiptStoreError::Conflict)?;
    let quote: ReceiptAppendQuoteData = quote_receipt_append(
        connection,
        &ReceiptAppendRecipeData {
            anchored,
            receipt_bytes,
            capability_id,
            minimum_page_bucket,
        },
    )?;
    if quote.disk_bytes() < quote.wal_bytes()
        || !quote.page_bucket().is_power_of_two()
        || quote.page_bucket() < minimum_page_bucket
        || quote.maximum_page_growth() == 0
        || quote.maximum_page_growth() > quote.page_bucket()
    {
        return Err(ReceiptStoreError::Conflict(
            "native receipt quote lost its own bounds".to_owned(),
        ));
    }
    Ok(NativeReceiptAppendQuote {
        device: file.device,
        inode: file.inode,
        wal_bytes: quote.wal_bytes(),
        disk_bytes: quote.disk_bytes(),
        wal_frames: quote.wal_frames(),
        page_bucket: quote.page_bucket(),
        page_growth: quote.maximum_page_growth(),
        fingerprint: quote.fingerprint().to_owned(),
    })
}

impl SqliteReceiptStore {
    /// Attach the native bank whose outstanding debt every later commit of
    /// this sink preserves. A sink serves exactly one native authority.
    pub(crate) fn attach_native_finishing_bank(
        &self,
        view: NativeReceiptBankViewData,
    ) -> Result<(), ReceiptStoreError> {
        self.native_debt.attach(&view)?;
        self.refresh_native_page_cap()
    }

    /// Recompute the ordinary page cap from the committed bank with the gate
    /// closed, so no checked-out connection keeps an older, larger cap.
    pub(crate) fn refresh_native_page_cap(&self) -> Result<(), ReceiptStoreError> {
        let Some(bank) = self.native_debt.bank.get() else {
            return Ok(());
        };
        let (device, inode) = self.native_receipt_file()?;
        let closed = self.native_debt.close()?;
        let debt = self.native_debt.read_debt(bank, device, inode)?;
        closed.set_native_page_cap(debt.as_ref());
        Ok(())
    }

    /// Publish new native debt on this sink atomically with its writer
    /// boundary. With the gate closed no receipt connection is checked out,
    /// so the sink's committed state is exact: it is checked against the debt
    /// the uncommitted native transaction carries, `publish` commits that
    /// transaction, and the new page cap applies before the gate reopens.
    pub(crate) fn publish_native_receipt_loan<T, E>(
        &self,
        debt: &NativeRegisteredFileDebtData,
        publish: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, ReceiptStoreError> {
        let path = self
            .connection()?
            .path()
            .map(str::to_owned)
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "native receipt sink requires a persistent file".to_owned(),
                )
            })?;
        let closed = self.native_debt.close()?;
        let observer =
            open_read_only(&path, Duration::from_secs(5)).map_err(ReceiptStoreError::Conflict)?;
        let pending_wal = crate::admission_operation_store::observed_wal_pressure(&observer)
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let available =
            main_database_available_bytes(&observer).map_err(ReceiptStoreError::Conflict)?;
        let pages = page_count(&observer).map_err(ReceiptStoreError::Conflict)?;
        require_page_budget(debt, pages, 0).map_err(ReceiptStoreError::Conflict)?;
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            pending_wal,
            available,
            &debt.this_file,
            &debt.other_files,
            &SqlitePhysicalDebtAmountData::checked(0, 0).map_err(ReceiptStoreError::Conflict)?,
        )
        .map_err(ReceiptStoreError::Conflict)?;
        let published = publish();
        if published.is_ok() {
            closed.set_native_page_cap(Some(debt));
        }
        Ok(published)
    }

    pub(crate) fn native_finishing_bank(&self) -> Option<&NativeReceiptBankViewData> {
        self.native_debt.bank.get()
    }

    /// The actual sink file's identity.
    pub(crate) fn native_receipt_file(&self) -> Result<(u64, u64), ReceiptStoreError> {
        let connection = self.connection()?;
        let file = main_database_file_identity(&connection).map_err(ReceiptStoreError::Conflict)?;
        Ok((file.device, file.inode))
    }

    /// Quote one native receipt append before the effect. The quote reads a
    /// dedicated read-only connection with the funded writer's cache profile.
    /// Its page bucket covers the current page count, every already owed
    /// loan's growth and its own growth, so no owed loan is invalidated.
    pub(crate) fn quote_native_receipt_append(
        &self,
        receipt_bytes: u64,
        capability_id: &str,
        owed_pages: u64,
    ) -> Result<NativeReceiptAppendQuote, ReceiptStoreError> {
        let path = self
            .connection()?
            .path()
            .map(str::to_owned)
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "native receipt sink requires a persistent file".to_owned(),
                )
            })?;
        let connection =
            open_read_only(&path, Duration::from_secs(5)).map_err(ReceiptStoreError::Conflict)?;
        connection.execute_batch("PRAGMA cache_spill = OFF")?;
        let anchored = self.rollback_anchor.is_some();
        let first = native_quote(&connection, receipt_bytes, capability_id, 1, anchored)?;
        let pages = page_count(&connection).map_err(ReceiptStoreError::Conflict)?;
        let floor = pages
            .checked_add(owed_pages)
            .and_then(|required| required.checked_add(first.page_growth))
            .and_then(u64::checked_next_power_of_two)
            .ok_or_else(|| {
                ReceiptStoreError::Conflict("native receipt page bucket exhausted".to_owned())
            })?;
        native_quote(&connection, receipt_bytes, capability_id, floor, anchored)
    }

    /// Whether any receipt lineage statement names `receipt_id`.
    pub(crate) fn native_receipt_named(&self, receipt_id: &str) -> Result<bool, ReceiptStoreError> {
        Ok(self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM receipt_lineage_statements
             WHERE receipt_id = ?1 OR parent_receipt_id = ?1)",
            [receipt_id],
            |row| row.get(0),
        )?)
    }

    /// Whether this exact receipt is already retained. A different receipt
    /// under the same identity refuses.
    pub(crate) fn native_receipt_retained(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<bool, ReceiptStoreError> {
        let Some(existing) =
            chio_kernel::receipt_store::ReceiptStore::load_chio_receipt(self, &receipt.id)?
        else {
            return Ok(false);
        };
        let canonical = |value: &ChioReceipt| {
            canonical_json_bytes(value)
                .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))
        };
        if canonical(&existing)? != canonical(receipt)? {
            return Err(ReceiptStoreError::Conflict(format!(
                "native receipt {} conflicts with its retained receipt",
                receipt.id
            )));
        }
        Ok(true)
    }

    /// Append the one receipt of a native original under its prepaid purpose.
    /// Inside the writer's transaction the sink is re-quoted at the retained
    /// recipe and must equal the account's priced profile, the funded
    /// capacity and page budget are checked, and the exact producer rows are
    /// written. The account spends its purpose only after this commits; an
    /// already retained receipt refuses here and is spent by the replay.
    pub(crate) fn append_native_finishing_receipt(
        &self,
        receipt: &ChioReceipt,
        pending_visible_at_ms: Option<u64>,
        funding: NativeReceiptFundingData,
    ) -> Result<(), ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        if let Some(visible) = pending_visible_at_ms {
            if self.settlement_store_binding.is_none() {
                return Err(ReceiptStoreError::Unsupported(
                    "atomic settlement observation projection".to_string(),
                ));
            }
            sqlite_i64(visible, "settlement attempt visibility deadline")?;
        }
        let canonical = canonical_json_bytes(receipt)
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        if !u64::try_from(canonical.len()).is_ok_and(|bytes| bytes <= funding.receipt_bytes) {
            return Err(ReceiptStoreError::Conflict(
                "native receipt exceeds its prepaid envelope".to_owned(),
            ));
        }
        let raw_json = serde_json::to_string(receipt)?;
        let receipt = receipt.clone();
        let anchored = self.rollback_anchor.is_some();
        self.writer_handle().run_write_receipt(move |tx| {
            let outcome = funded_append(
                tx,
                &receipt,
                &raw_json,
                pending_visible_at_ms,
                &funding,
                anchored,
            );
            if outcome.is_err() {
                FUNDED_COMMIT.with(|funded| funded.set(None));
            }
            outcome
        })
    }
}

/// The exact producer rows of one funded native receipt append.
fn funded_append(
    tx: &rusqlite::Transaction<'_>,
    receipt: &ChioReceipt,
    raw_json: &str,
    pending_visible_at_ms: Option<u64>,
    funding: &NativeReceiptFundingData,
    anchored: bool,
) -> Result<(), ReceiptStoreError> {
    // The quoted frame bound is this transaction's whole dirty-page set.
    let spill: i64 = tx.query_row("PRAGMA cache_spill", [], |row| row.get(0))?;
    tx.execute_batch("PRAGMA cache_spill = OFF")?;
    SPILL_RESTORE.with(|restore| restore.set(Some(spill != 0)));
    let quote = native_quote(
        tx,
        funding.receipt_bytes,
        receipt.capability_id.as_str(),
        funding.page_bucket,
        anchored,
    )?;
    let profile = native_receipt_sink_profile(
        &quote,
        &funding.registration_digest,
        funding.receipt_bytes,
        receipt.capability_id.as_str(),
    )?;
    if profile != funding.profile_digest
        || (quote.wal_bytes, quote.disk_bytes) != (funding.wal_bytes, funding.disk_bytes)
        || (quote.page_bucket, quote.page_growth) != (funding.page_bucket, funding.page_growth)
    {
        return Err(ReceiptStoreError::Conflict(
            "native receipt sink differs from its priced purpose".to_owned(),
        ));
    }
    let named: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM receipt_lineage_statements
         WHERE receipt_id = ?1 OR parent_receipt_id = ?1)",
        [receipt.id.as_str()],
        |row| row.get(0),
    )?;
    if named {
        return Err(ReceiptStoreError::Conflict(
            "owed native receipt was named by another lineage statement".to_owned(),
        ));
    }
    FUNDED_COMMIT.with(|funded| {
        funded.set(Some(FundedCommit {
            wal_bytes: quote.wal_bytes,
            disk_bytes: quote.disk_bytes,
            page_growth: quote.page_growth,
        }))
    });
    require_receipt_commit(tx)?;
    ensure_checkpoint_transparency_guards(tx)?;
    let (_, inserted) = append_chio_receipt_tx_with_insert_status(tx, receipt, raw_json)?;
    if !inserted {
        return Err(ReceiptStoreError::Conflict(
            "native receipt is already retained".to_owned(),
        ));
    }
    ensure_receipt_lineage_statement_for_receipt_id_tx(tx, &receipt.id)?;
    if let Some(visible) = pending_visible_at_ms {
        crate::settle_attempts::insert_attempt_zero_tx(
            tx,
            &receipt.id,
            receipt.timestamp,
            visible,
        )?;
    }
    Ok(())
}
