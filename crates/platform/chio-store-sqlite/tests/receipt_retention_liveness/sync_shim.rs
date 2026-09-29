//! A SQLite VFS layered over the process default that observes `xSync` and
//! keeps a per-handle ledger of file and WAL-index locks.
//!
//! Every method forwards to the wrapped VFS unchanged. `xSync` additionally
//! records the calling thread and file, applies an optional fixed delay (the
//! fsync latency of a slow disk), and can hold one selected sync at a gate
//! until the test releases it, which is how a stall is placed at an exact
//! durability boundary without a timing assumption. `xLock`, `xUnlock`,
//! `xShmLock` and `xClose` maintain the ledger, so a snapshot taken while a
//! sync is held names the thread that owns the WAL write lock.
//!
//! The shim registers itself as the default VFS once per process, so every
//! connection the store opens afterwards (main database, WAL and attached
//! archive alike) is observed. Its name deliberately does not start with
//! `unix`: a qualified-sink identity probe fails closed instead of reading a
//! foreign file layout.
#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::fmt;
use std::mem::size_of;
use std::ptr;
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use rusqlite::ffi;

#[path = "sync_diagnostics.rs"]
mod diagnostics;

const SHIM_NAME: &CStr = c"chio-sync-shim";

/// Identity of the thread that issued a VFS call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadTag {
    pub id: ThreadId,
    pub name: Option<String>,
}

impl ThreadTag {
    fn current() -> Self {
        let current = thread::current();
        Self {
            id: current.id(),
            name: current.name().map(str::to_owned),
        }
    }
}

impl fmt::Display for ThreadTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(formatter, "{name} ({:?})", self.id),
            None => write!(formatter, "unnamed ({:?})", self.id),
        }
    }
}

/// The role SQLite declared for a file when it opened it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileKind {
    MainDb,
    Wal,
    MainJournal,
    TempDb,
    TempJournal,
    SubJournal,
    SuperJournal,
    Other,
}

impl FileKind {
    fn classify(flags: c_int) -> Self {
        if flags & ffi::SQLITE_OPEN_MAIN_DB != 0 {
            Self::MainDb
        } else if flags & ffi::SQLITE_OPEN_WAL != 0 {
            Self::Wal
        } else if flags & ffi::SQLITE_OPEN_MAIN_JOURNAL != 0 {
            Self::MainJournal
        } else if flags & ffi::SQLITE_OPEN_TEMP_DB != 0 {
            Self::TempDb
        } else if flags & ffi::SQLITE_OPEN_TEMP_JOURNAL != 0 {
            Self::TempJournal
        } else if flags & ffi::SQLITE_OPEN_SUBJOURNAL != 0 {
            Self::SubJournal
        } else if flags & ffi::SQLITE_OPEN_SUPER_JOURNAL != 0 {
            Self::SuperJournal
        } else {
            Self::Other
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::MainDb => "main",
            Self::Wal => "wal",
            Self::MainJournal => "journal",
            Self::TempDb => "temp",
            Self::TempJournal => "temp-journal",
            Self::SubJournal => "sub-journal",
            Self::SuperJournal => "super-journal",
            Self::Other => "other",
        }
    }
}

/// One `xSync` call as the shim observed it.
#[derive(Clone, Debug)]
pub struct SyncRecord {
    pub thread: ThreadTag,
    pub path: String,
    pub kind: FileKind,
    pub flags: c_int,
    pub started: Instant,
    /// Exclusive WAL-index locks held by this thread when xSync begins.
    pub wal_write_lock: bool,
    pub wal_checkpoint_lock: bool,
    /// Captured only for a gated sync, on the blocked thread itself.
    pub backtrace: Option<String>,
}

impl fmt::Display for SyncRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "xSync(flags={}) on {} [{}] by {}",
            self.flags,
            self.path,
            self.kind.label(),
            self.thread
        )
    }
}

/// Which sync the gate holds: the `(skip + 1)`-th sync of `kind` on a file
/// whose path starts with `path_prefix`.
#[derive(Clone, Debug)]
pub struct GateSpec {
    pub path_prefix: String,
    pub kind: FileKind,
    pub skip: u32,
}

/// Lock state of one SQLite file handle.
#[derive(Clone, Debug, Default)]
struct HandleLocks {
    level: c_int,
    locker: Option<ThreadTag>,
    /// WAL-index lock slot to (exclusive, holder).
    shm: BTreeMap<c_int, (bool, ThreadTag)>,
}

impl HandleLocks {
    fn is_idle(&self) -> bool {
        self.level <= ffi::SQLITE_LOCK_NONE && self.shm.is_empty()
    }
}

#[derive(Default)]
struct State {
    armed: Option<GateSpec>,
    matched: u32,
    blocked: Option<SyncRecord>,
    released: bool,
    delay: Duration,
    history: Vec<SyncRecord>,
    /// path -> handle address -> locks
    locks: BTreeMap<String, BTreeMap<usize, HandleLocks>>,
    handle_paths: BTreeMap<usize, String>,
}

/// Process-wide shim control surface.
pub struct SyncShim {
    active_syncs: diagnostics::ActiveSyncs,
    state: Mutex<State>,
    changed: Condvar,
}

static SHIM: OnceLock<SyncShim> = OnceLock::new();
static REGISTRATION: OnceLock<Result<(), String>> = OnceLock::new();

/// Register the shim as the default VFS (once) and return its control handle.
pub fn install() -> &'static SyncShim {
    let shim = SHIM.get_or_init(|| SyncShim {
        active_syncs: diagnostics::ActiveSyncs::default(),
        state: Mutex::new(State::default()),
        changed: Condvar::new(),
    });
    let registration = REGISTRATION.get_or_init(register_default_vfs);
    if let Err(reason) = registration {
        panic!("sync shim registration failed: {reason}");
    }
    shim
}

fn register_default_vfs() -> Result<(), String> {
    // SAFETY: sqlite3_initialize is idempotent and thread-safe under
    // SQLITE_THREADSAFE=1, which the bundled build sets.
    let initialized = unsafe { ffi::sqlite3_initialize() };
    if initialized != ffi::SQLITE_OK {
        return Err(format!("sqlite3_initialize returned {initialized}"));
    }
    // SAFETY: a null name selects the current default VFS.
    let parent = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
    if parent.is_null() {
        return Err("no default SQLite VFS is registered".to_owned());
    }
    // SAFETY: `parent` was returned by SQLite and stays registered for the
    // life of the process; only public fields are read.
    let parent_fields = unsafe { &*parent };
    let (parent_version, parent_file_size, parent_path_max) = (
        parent_fields.iVersion,
        parent_fields.szOsFile,
        parent_fields.mxPathname,
    );
    if parent_version < 3 {
        return Err(format!(
            "the default VFS is version {parent_version}; the shim forwards version 3"
        ));
    }
    let file_size = c_int::try_from(size_of::<ShimFile>())
        .map_err(|_| "shim file header does not fit a C int".to_owned())?
        .checked_add(parent_file_size)
        .ok_or_else(|| "shim file size overflowed".to_owned())?;
    let vfs = Box::new(ffi::sqlite3_vfs {
        iVersion: 3,
        szOsFile: file_size,
        mxPathname: parent_path_max,
        pNext: ptr::null_mut(),
        zName: SHIM_NAME.as_ptr(),
        pAppData: parent.cast(),
        xOpen: Some(shim_open),
        xDelete: Some(shim_delete),
        xAccess: Some(shim_access),
        xFullPathname: Some(shim_full_pathname),
        xDlOpen: Some(shim_dl_open),
        xDlError: Some(shim_dl_error),
        xDlSym: Some(shim_dl_sym),
        xDlClose: Some(shim_dl_close),
        xRandomness: Some(shim_randomness),
        xSleep: Some(shim_sleep),
        xCurrentTime: Some(shim_current_time),
        xGetLastError: Some(shim_get_last_error),
        xCurrentTimeInt64: Some(shim_current_time_int64),
        xSetSystemCall: Some(shim_set_system_call),
        xGetSystemCall: Some(shim_get_system_call),
        xNextSystemCall: Some(shim_next_system_call),
    });
    // The registration is permanent, so the VFS object must outlive every
    // connection: leak it.
    let vfs = Box::leak(vfs);
    // SAFETY: `vfs` is a fully initialized, 'static sqlite3_vfs whose name is
    // a 'static C string; makeDflt=1 installs it as the process default.
    let registered = unsafe { ffi::sqlite3_vfs_register(vfs, 1) };
    if registered != ffi::SQLITE_OK {
        return Err(format!("sqlite3_vfs_register returned {registered}"));
    }
    Ok(())
}

impl SyncShim {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Hold the selected sync at the gate until `release`.
    pub fn arm(&self, spec: GateSpec) {
        let mut state = self.state();
        state.armed = Some(spec);
        state.matched = 0;
        state.blocked = None;
        state.released = false;
    }

    /// Forget an armed gate that never tripped.
    pub fn disarm(&self) {
        self.state().armed = None;
    }

    /// Wait until the armed sync is held at the gate.
    pub fn wait_for_block(&self, timeout: Duration) -> Option<SyncRecord> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        while state.blocked.is_none() {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
        state.blocked.clone()
    }

    /// Let the held sync proceed.
    pub fn release(&self) {
        let mut state = self.state();
        state.released = true;
        self.changed.notify_all();
    }

    /// Fixed latency added to every sync, the shape of a slow disk.
    pub fn set_delay(&self, delay: Duration) {
        self.state().delay = delay;
    }

    pub fn clear_history(&self) {
        self.state().history.clear();
    }

    /// Every recorded sync on files under `path_prefix`, in order.
    pub fn syncs_under(&self, path_prefix: &str) -> Vec<SyncRecord> {
        self.state()
            .history
            .iter()
            .filter(|record| record.path.starts_with(path_prefix))
            .cloned()
            .collect()
    }

    /// The lock ledger for files under `path_prefix`, rendered for a report.
    pub fn locks_under(&self, path_prefix: &str) -> String {
        let state = self.state();
        let mut rendered = String::new();
        for (path, handles) in state
            .locks
            .iter()
            .filter(|(path, _)| path.starts_with(path_prefix))
        {
            for (handle, locks) in handles.iter().filter(|(_, locks)| !locks.is_idle()) {
                rendered.push_str(&format!(
                    "  {path} handle {handle:#x}: file lock {}",
                    lock_level_name(locks.level)
                ));
                if let Some(locker) = &locks.locker {
                    rendered.push_str(&format!(" (last changed by {locker})"));
                }
                for (slot, (exclusive, holder)) in &locks.shm {
                    rendered.push_str(&format!(
                        ", wal-index {} {} by {holder}",
                        wal_slot_name(*slot),
                        if *exclusive { "EXCLUSIVE" } else { "SHARED" }
                    ));
                }
                rendered.push('\n');
            }
        }
        if rendered.is_empty() {
            rendered.push_str("  (no locks held)\n");
        }
        rendered
    }

    /// The sync currently held at the gate, the lock ledger and the kernel
    /// state of every thread in this process.
    pub fn snapshot(&self, path_prefix: &str) -> String {
        let blocked = self.state().blocked.clone();
        let mut report = String::from("held sync:\n");
        match blocked {
            Some(record) => {
                report.push_str(&format!(
                    "  {record}, held for {:?}\n",
                    record.started.elapsed()
                ));
                if let Some(backtrace) = &record.backtrace {
                    report.push_str("  backtrace of the syncing thread:\n");
                    for line in backtrace.lines() {
                        report.push_str("    ");
                        report.push_str(line);
                        report.push('\n');
                    }
                }
            }
            None => report.push_str("  (none)\n"),
        }
        report.push_str(&self.active_syncs.snapshot(path_prefix));
        report.push_str("lock ledger:\n");
        report.push_str(&self.locks_under(path_prefix));
        report.push_str("threads:\n");
        report.push_str(&thread_states());
        report
    }

    fn before_sync(
        &self,
        handle: usize,
        mut record: SyncRecord,
    ) -> diagnostics::SyncObservation<'_> {
        let mut state = self.state();
        if record.kind == FileKind::Wal {
            if let Some(main_path) = record.path.strip_suffix("-wal") {
                let held_by_this_thread = |slot| {
                    state.locks.get(main_path).is_some_and(|handles| {
                        handles.values().any(|locks| {
                            locks.shm.get(&slot).is_some_and(|(exclusive, holder)| {
                                *exclusive && holder.id == record.thread.id
                            })
                        })
                    })
                };
                // WAL_WRITE_LOCK and WAL_CKPT_LOCK in the bundled wal.c.
                record.wal_write_lock = held_by_this_thread(0);
                record.wal_checkpoint_lock = held_by_this_thread(1);
            }
        }
        let active = self.active_syncs.enter(handle, record.clone());
        let delay = state.delay;
        let gated = match &state.armed {
            Some(spec)
                if spec.kind == record.kind && record.path.starts_with(&spec.path_prefix) =>
            {
                if state.matched < spec.skip {
                    state.matched += 1;
                    false
                } else {
                    true
                }
            }
            _ => false,
        };
        state.history.push(record.clone());
        if gated {
            state.armed = None;
            state.released = false;
            let mut held = record;
            held.backtrace = Some(std::backtrace::Backtrace::force_capture().to_string());
            state.blocked = Some(held);
            self.changed.notify_all();
            while !state.released {
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            state.blocked = None;
            state.released = false;
        }
        drop(state);
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        active
    }

    fn record_lock(&self, handle: usize, path: &str, level: c_int) {
        let mut state = self.state();
        let locks = state
            .locks
            .entry(path.to_owned())
            .or_default()
            .entry(handle)
            .or_default();
        locks.level = level;
        locks.locker = Some(ThreadTag::current());
        state.handle_paths.insert(handle, path.to_owned());
    }

    fn record_shm_lock(&self, handle: usize, path: &str, offset: c_int, n: c_int, flags: c_int) {
        let mut state = self.state();
        let locks = state
            .locks
            .entry(path.to_owned())
            .or_default()
            .entry(handle)
            .or_default();
        for slot in offset..offset.saturating_add(n) {
            if flags & ffi::SQLITE_SHM_UNLOCK != 0 {
                locks.shm.remove(&slot);
            } else {
                locks.shm.insert(
                    slot,
                    (flags & ffi::SQLITE_SHM_EXCLUSIVE != 0, ThreadTag::current()),
                );
            }
        }
        state.handle_paths.insert(handle, path.to_owned());
    }

    fn forget_handle(&self, handle: usize) {
        let mut state = self.state();
        if let Some(path) = state.handle_paths.remove(&handle) {
            if let Some(handles) = state.locks.get_mut(&path) {
                handles.remove(&handle);
            }
        }
    }
}

fn lock_level_name(level: c_int) -> &'static str {
    match level {
        ffi::SQLITE_LOCK_NONE => "NONE",
        ffi::SQLITE_LOCK_SHARED => "SHARED",
        ffi::SQLITE_LOCK_RESERVED => "RESERVED",
        ffi::SQLITE_LOCK_PENDING => "PENDING",
        ffi::SQLITE_LOCK_EXCLUSIVE => "EXCLUSIVE",
        _ => "UNKNOWN",
    }
}

/// WAL-index lock slot names from SQLite's wal.c.
pub fn wal_slot_name(slot: c_int) -> String {
    match slot {
        0 => "WRITE".to_owned(),
        1 => "CKPT".to_owned(),
        2 => "RECOVER".to_owned(),
        other => format!("READ({})", other - 3),
    }
}

/// Kernel-side view of every thread: name, scheduler state, wait channel and
/// the syscall it is blocked in (raw `/proc/self/task/<tid>/syscall`).
pub fn thread_states() -> String {
    let mut rendered = String::new();
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return "  (procfs unavailable)\n".to_owned();
    };
    for task in tasks.flatten() {
        let base = task.path();
        let read = |name: &str| {
            std::fs::read_to_string(base.join(name))
                .map(|text| text.trim().to_owned())
                .unwrap_or_else(|_| "?".to_owned())
        };
        let state = read("status")
            .lines()
            .find_map(|line| {
                line.strip_prefix("State:")
                    .map(|rest| rest.trim().to_owned())
            })
            .unwrap_or_else(|| "?".to_owned());
        rendered.push_str(&format!(
            "  tid {} {:<28} state={} wchan={} syscall={}\n",
            task.file_name().to_string_lossy(),
            read("comm"),
            state,
            read("wchan"),
            read("syscall")
        ));
    }
    rendered
}

/// The shim's file object. SQLite allocates `szOsFile` bytes; the wrapped
/// VFS's own object lives immediately after this header.
#[repr(C)]
struct ShimFile {
    base: ffi::sqlite3_file,
    real: *mut ffi::sqlite3_file,
    path: *const c_char,
    kind: FileKind,
}

fn shim() -> &'static SyncShim {
    install()
}

// Casting a pointer does not access it; dereferencing the result remains unsafe.
fn header(file: *mut ffi::sqlite3_file) -> *mut ShimFile {
    file.cast::<ShimFile>()
}

/// # Safety
/// `file` must be an initialized shim object whose wrapped file installed a
/// method table, including a failed open that requires xClose cleanup.
unsafe fn real_parts(
    file: *mut ffi::sqlite3_file,
) -> (*mut ffi::sqlite3_file, ffi::sqlite3_io_methods) {
    // SAFETY: the caller guarantees an initialized ShimFile header.
    let real = unsafe { (*header(file)).real };
    // SAFETY: the wrapped object is initialized and has a method table.
    let table = unsafe { (*real).pMethods };
    // SAFETY: SQLite's method table remains valid for the open file's lifetime.
    let methods = unsafe { *table };
    (real, methods)
}

/// # Safety
/// `file` must be a shim file object that `shim_open` initialized.
unsafe fn file_path(file: *mut ffi::sqlite3_file) -> String {
    // SAFETY: the caller guarantees an initialized ShimFile header.
    let path = unsafe { (*header(file)).path };
    if path.is_null() {
        String::from("<unnamed>")
    } else {
        // SAFETY: SQLite keeps the NUL-terminated open filename valid until xClose.
        unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .into_owned()
    }
}

/// # Safety
/// `vfs` must be the shim VFS registered by `register_default_vfs`.
unsafe fn parent_of(vfs: *mut ffi::sqlite3_vfs) -> *mut ffi::sqlite3_vfs {
    // SAFETY: pAppData was set to the wrapped VFS at registration.
    unsafe { (*vfs).pAppData.cast::<ffi::sqlite3_vfs>() }
}

unsafe extern "C" fn shim_open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    // SAFETY: SQLite dispatches this callback through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    let shim_file = header(file);
    // SAFETY: szOsFile reserves the aligned header followed by the parent's object.
    let real = unsafe { file.cast::<u8>().add(size_of::<ShimFile>()) }.cast::<ffi::sqlite3_file>();
    // SAFETY: the leading allocation fits ShimFile. Write the entire header before
    // reading any field, including its Rust enum discriminant.
    unsafe {
        shim_file.write(ShimFile {
            base: ffi::sqlite3_file {
                pMethods: ptr::null(),
            },
            real,
            path: name,
            kind: FileKind::classify(flags),
        })
    };
    // SAFETY: the trailing allocation fits the parent's sqlite3_file prefix.
    unsafe { (*real).pMethods = ptr::null() };
    // SAFETY: the registered parent VFS remains alive during the callback.
    let open = unsafe { (*parent).xOpen };
    let Some(open) = open else {
        return ffi::SQLITE_CANTOPEN;
    };
    // SAFETY: forward SQLite's arguments with the parent's correctly sized object.
    let rc = unsafe { open(parent, name, real, flags, out_flags) };
    // SAFETY: the parent initialized pMethods, or left our null sentinel intact.
    let needs_close = unsafe { !(*real).pMethods.is_null() };
    // SQLite also closes failed opens when the parent installed a method table.
    if needs_close {
        // SAFETY: only the header's method pointer is changed, after initialization.
        unsafe { (*shim_file).base.pMethods = &SHIM_METHODS };
    }
    rc
}

unsafe extern "C" fn shim_delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xDelete };
    match method {
        Some(delete) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { delete(parent, name, sync_dir) }
        }
        None => ffi::SQLITE_IOERR_DELETE,
    }
}

unsafe extern "C" fn shim_access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    result: *mut c_int,
) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xAccess };
    match method {
        Some(access) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { access(parent, name, flags, result) }
        }
        None => ffi::SQLITE_IOERR_ACCESS,
    }
}

unsafe extern "C" fn shim_full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    out_len: c_int,
    out: *mut c_char,
) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xFullPathname };
    match method {
        Some(full_pathname) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { full_pathname(parent, name, out_len, out) }
        }
        None => ffi::SQLITE_ERROR,
    }
}

unsafe extern "C" fn shim_dl_open(vfs: *mut ffi::sqlite3_vfs, name: *const c_char) -> *mut c_void {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xDlOpen };
    match method {
        Some(dl_open) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { dl_open(parent, name) }
        }
        None => ptr::null_mut(),
    }
}

unsafe extern "C" fn shim_dl_error(vfs: *mut ffi::sqlite3_vfs, len: c_int, message: *mut c_char) {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xDlError };
    if let Some(dl_error) = method {
        // SAFETY: forwards the original SQLite arguments to the wrapped callback.
        unsafe { dl_error(parent, len, message) };
    }
}

unsafe extern "C" fn shim_dl_sym(
    vfs: *mut ffi::sqlite3_vfs,
    handle: *mut c_void,
    symbol: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xDlSym };
    match method {
        Some(dl_sym) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { dl_sym(parent, handle, symbol) }
        }
        None => None,
    }
}

unsafe extern "C" fn shim_dl_close(vfs: *mut ffi::sqlite3_vfs, handle: *mut c_void) {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xDlClose };
    if let Some(dl_close) = method {
        // SAFETY: forwards the original SQLite arguments to the wrapped callback.
        unsafe { dl_close(parent, handle) };
    }
}

unsafe extern "C" fn shim_randomness(
    vfs: *mut ffi::sqlite3_vfs,
    len: c_int,
    out: *mut c_char,
) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xRandomness };
    match method {
        Some(randomness) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { randomness(parent, len, out) }
        }
        None => 0,
    }
}

unsafe extern "C" fn shim_sleep(vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xSleep };
    match method {
        Some(sleep) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { sleep(parent, microseconds) }
        }
        None => 0,
    }
}

unsafe extern "C" fn shim_current_time(vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xCurrentTime };
    match method {
        Some(current_time) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { current_time(parent, out) }
        }
        None => ffi::SQLITE_ERROR,
    }
}

unsafe extern "C" fn shim_get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    len: c_int,
    out: *mut c_char,
) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xGetLastError };
    match method {
        Some(get_last_error) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { get_last_error(parent, len, out) }
        }
        None => 0,
    }
}

unsafe extern "C" fn shim_current_time_int64(
    vfs: *mut ffi::sqlite3_vfs,
    out: *mut ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xCurrentTimeInt64 };
    match method {
        Some(current_time) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { current_time(parent, out) }
        }
        None => ffi::SQLITE_ERROR,
    }
}

unsafe extern "C" fn shim_set_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    call: ffi::sqlite3_syscall_ptr,
) -> c_int {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xSetSystemCall };
    match method {
        Some(set_system_call) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { set_system_call(parent, name, call) }
        }
        None => ffi::SQLITE_NOTFOUND,
    }
}

unsafe extern "C" fn shim_get_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> ffi::sqlite3_syscall_ptr {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xGetSystemCall };
    match method {
        Some(get_system_call) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { get_system_call(parent, name) }
        }
        None => None,
    }
}

unsafe extern "C" fn shim_next_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> *const c_char {
    // SAFETY: SQLite called through our registered VFS.
    let parent = unsafe { parent_of(vfs) };
    // SAFETY: the registered parent VFS remains alive during this callback.
    let method = unsafe { (*parent).xNextSystemCall };
    match method {
        Some(next_system_call) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { next_system_call(parent, name) }
        }
        None => ptr::null(),
    }
}

static SHIM_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 3,
    xClose: Some(shim_close),
    xRead: Some(shim_read),
    xWrite: Some(shim_write),
    xTruncate: Some(shim_truncate),
    xSync: Some(shim_sync),
    xFileSize: Some(shim_file_size),
    xLock: Some(shim_lock),
    xUnlock: Some(shim_unlock),
    xCheckReservedLock: Some(shim_check_reserved_lock),
    xFileControl: Some(shim_file_control),
    xSectorSize: Some(shim_sector_size),
    xDeviceCharacteristics: Some(shim_device_characteristics),
    xShmMap: Some(shim_shm_map),
    xShmLock: Some(shim_shm_lock),
    xShmBarrier: Some(shim_shm_barrier),
    xShmUnmap: Some(shim_shm_unmap),
    xFetch: Some(shim_fetch),
    xUnfetch: Some(shim_unfetch),
};

unsafe extern "C" fn shim_close(file: *mut ffi::sqlite3_file) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    let rc = match methods.xClose {
        Some(close) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { close(real) }
        }
        None => ffi::SQLITE_IOERR_CLOSE,
    };
    shim().forget_handle(file as usize);
    rc
}

unsafe extern "C" fn shim_read(
    file: *mut ffi::sqlite3_file,
    buffer: *mut c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xRead {
        Some(read) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { read(real, buffer, amount, offset) }
        }
        None => ffi::SQLITE_IOERR_READ,
    }
}

unsafe extern "C" fn shim_write(
    file: *mut ffi::sqlite3_file,
    buffer: *const c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xWrite {
        Some(write) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { write(real, buffer, amount, offset) }
        }
        None => ffi::SQLITE_IOERR_WRITE,
    }
}

unsafe extern "C" fn shim_truncate(
    file: *mut ffi::sqlite3_file,
    size: ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xTruncate {
        Some(truncate) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { truncate(real, size) }
        }
        None => ffi::SQLITE_IOERR_TRUNCATE,
    }
}

unsafe extern "C" fn shim_sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    let record = SyncRecord {
        thread: ThreadTag::current(),
        // SAFETY: SQLite keeps the filename live until xClose.
        path: unsafe { file_path(file) },
        // SAFETY: shim_open initialized this header before installing the method table.
        kind: unsafe { (*header(file)).kind },
        flags,
        started: Instant::now(),
        wal_write_lock: false,
        wal_checkpoint_lock: false,
        backtrace: None,
    };
    let _active_sync = shim().before_sync(file.addr(), record);
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xSync {
        Some(sync) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { sync(real, flags) }
        }
        None => ffi::SQLITE_IOERR_FSYNC,
    }
}

unsafe extern "C" fn shim_file_size(
    file: *mut ffi::sqlite3_file,
    size: *mut ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xFileSize {
        Some(file_size) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { file_size(real, size) }
        }
        None => ffi::SQLITE_IOERR_FSTAT,
    }
}

unsafe extern "C" fn shim_lock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    let rc = match methods.xLock {
        Some(lock) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { lock(real, level) }
        }
        None => ffi::SQLITE_IOERR_LOCK,
    };
    if rc == ffi::SQLITE_OK {
        // SAFETY: this initialized file is still open.
        let path = unsafe { file_path(file) };
        shim().record_lock(file as usize, &path, level);
    }
    rc
}

unsafe extern "C" fn shim_unlock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    let rc = match methods.xUnlock {
        Some(unlock) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { unlock(real, level) }
        }
        None => ffi::SQLITE_IOERR_UNLOCK,
    };
    if rc == ffi::SQLITE_OK {
        // SAFETY: this initialized file is still open.
        let path = unsafe { file_path(file) };
        shim().record_lock(file as usize, &path, level);
    }
    rc
}

unsafe extern "C" fn shim_check_reserved_lock(
    file: *mut ffi::sqlite3_file,
    result: *mut c_int,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xCheckReservedLock {
        Some(check) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { check(real, result) }
        }
        None => ffi::SQLITE_IOERR_CHECKRESERVEDLOCK,
    }
}

unsafe extern "C" fn shim_file_control(
    file: *mut ffi::sqlite3_file,
    op: c_int,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xFileControl {
        Some(file_control) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { file_control(real, op, arg) }
        }
        None => ffi::SQLITE_NOTFOUND,
    }
}

unsafe extern "C" fn shim_sector_size(file: *mut ffi::sqlite3_file) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xSectorSize {
        Some(sector_size) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { sector_size(real) }
        }
        None => 4096,
    }
}

unsafe extern "C" fn shim_device_characteristics(file: *mut ffi::sqlite3_file) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xDeviceCharacteristics {
        Some(characteristics) => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { characteristics(real) }
        }
        None => 0,
    }
}

unsafe extern "C" fn shim_shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    page_size: c_int,
    extend: c_int,
    out: *mut *mut c_void,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xShmMap {
        Some(shm_map) if methods.iVersion >= 2 => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { shm_map(real, page, page_size, extend, out) }
        }
        _ => ffi::SQLITE_IOERR_SHMMAP,
    }
}

unsafe extern "C" fn shim_shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    n: c_int,
    flags: c_int,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    let rc = match methods.xShmLock {
        Some(shm_lock) if methods.iVersion >= 2 => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { shm_lock(real, offset, n, flags) }
        }
        _ => ffi::SQLITE_IOERR_SHMLOCK,
    };
    if rc == ffi::SQLITE_OK {
        // SAFETY: this initialized file is still open.
        let path = unsafe { file_path(file) };
        shim().record_shm_lock(file as usize, &path, offset, n, flags);
    }
    rc
}

unsafe extern "C" fn shim_shm_barrier(file: *mut ffi::sqlite3_file) {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    if let Some(barrier) = methods.xShmBarrier {
        if methods.iVersion >= 2 {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { barrier(real) };
        }
    }
}

unsafe extern "C" fn shim_shm_unmap(file: *mut ffi::sqlite3_file, delete: c_int) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xShmUnmap {
        Some(shm_unmap) if methods.iVersion >= 2 => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { shm_unmap(real, delete) }
        }
        _ => ffi::SQLITE_OK,
    }
}

unsafe extern "C" fn shim_fetch(
    file: *mut ffi::sqlite3_file,
    offset: ffi::sqlite3_int64,
    amount: c_int,
    out: *mut *mut c_void,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xFetch {
        Some(fetch) if methods.iVersion >= 3 => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { fetch(real, offset, amount, out) }
        }
        _ => {
            // SAFETY: SQLite supplies a writable output pointer for xFetch.
            unsafe { *out = ptr::null_mut() };
            ffi::SQLITE_OK
        }
    }
}

unsafe extern "C" fn shim_unfetch(
    file: *mut ffi::sqlite3_file,
    offset: ffi::sqlite3_int64,
    page: *mut c_void,
) -> c_int {
    // SAFETY: SQLite invokes I/O methods only after a method table is installed.
    let (real, methods) = unsafe { real_parts(file) };
    match methods.xUnfetch {
        Some(unfetch) if methods.iVersion >= 3 => {
            // SAFETY: forwards the original SQLite arguments to the wrapped callback.
            unsafe { unfetch(real, offset, page) }
        }
        _ => ffi::SQLITE_OK,
    }
}

#[cfg(test)]
mod failed_open_tests {
    use super::*;
    use std::mem::MaybeUninit;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CLOSES: AtomicUsize = AtomicUsize::new(0);
    static METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
        xClose: Some(close_failed_file),
        ..SHIM_METHODS
    };

    unsafe extern "C" fn close_failed_file(_file: *mut ffi::sqlite3_file) -> c_int {
        CLOSES.fetch_add(1, Ordering::SeqCst);
        ffi::SQLITE_OK
    }

    unsafe extern "C" fn open_then_fail(
        _vfs: *mut ffi::sqlite3_vfs,
        _name: ffi::sqlite3_filename,
        file: *mut ffi::sqlite3_file,
        _flags: c_int,
        _out_flags: *mut c_int,
    ) -> c_int {
        // SAFETY: shim_open supplies space for the wrapped sqlite3_file.
        unsafe { (*file).pMethods = &METHODS };
        ffi::SQLITE_CANTOPEN
    }

    #[test]
    fn failed_parent_open_keeps_its_required_close_callback() {
        let _exclusive = super::super::exclusive();
        #[repr(C)]
        struct Storage {
            header: MaybeUninit<ShimFile>,
            real: MaybeUninit<ffi::sqlite3_file>,
        }
        assert_eq!(std::mem::offset_of!(Storage, real), size_of::<ShimFile>());
        // SAFETY: sqlite3_vfs contains integers, raw pointers and nullable
        // function pointers. Fields used by this local call are filled below.
        let mut parent: ffi::sqlite3_vfs = unsafe { std::mem::zeroed() };
        parent.xOpen = Some(open_then_fail);
        // SAFETY: same C-struct layout as parent; only pAppData is read here.
        let mut wrapper: ffi::sqlite3_vfs = unsafe { std::mem::zeroed() };
        wrapper.pAppData = (&raw mut parent).cast();
        let mut storage = MaybeUninit::<Storage>::uninit();
        let file = storage.as_mut_ptr().cast::<ffi::sqlite3_file>();
        let before = CLOSES.load(Ordering::SeqCst);
        // SAFETY: the aligned allocation has the shim header and wrapped file,
        // and both VFS objects and the filename outlive open and close.
        let rc = unsafe {
            shim_open(
                &raw mut wrapper,
                c"failed-open".as_ptr(),
                file,
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(rc, ffi::SQLITE_CANTOPEN);
        // SAFETY: shim_open initialized the header even on failure.
        let methods = unsafe { (*file).pMethods };
        assert!(!methods.is_null(), "failed parent open requires cleanup");
        // SAFETY: published methods are static and the wrapped file initialized
        // its own method table before returning failure.
        assert_eq!(unsafe { shim_close(file) }, ffi::SQLITE_OK);
        assert_eq!(CLOSES.load(Ordering::SeqCst), before + 1);
    }
}
