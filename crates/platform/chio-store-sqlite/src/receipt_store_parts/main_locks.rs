/// Sidecar locks marking this instance as a live writer on a shared database
/// file and coordinating dispatch-intent reconciliation with its siblings.
pub(crate) struct WriterLifetimeLock {
    /// Shared advisory lock held for the store's lifetime, released by the
    /// OS when the process exits (cleanly or not): its continuous presence
    /// is what proves this instance live to its siblings. Reconciliation
    /// converts it to exclusive only to claim rows that name no probeable
    /// owner, proving no sibling is live at all, and only ever under the
    /// probe mutex, because flock conversions are not atomic and drop the
    /// mark for an instant while they resolve.
    pub(crate) mark: std::fs::File,
    /// Path of the sidecar mutex serializing sibling reconcile passes.
    /// Opened and locked per pass; closing the descriptor releases it, so
    /// an aborted pass can never leave the mutex held.
    pub(crate) probe_path: std::path::PathBuf,
    /// Database path the sidecar lock files derive from, kept to derive the
    /// owner-mark paths of foreign tokens found in the journal.
    pub(crate) database_path: std::path::PathBuf,
    /// This instance's own per-owner liveness mark, held (never read) so
    /// sibling reconcile passes defer exactly this instance's rows while
    /// it lives.
    pub(crate) _owner_mark: OwnerLivenessMark,
}

/// Per-owner liveness mark: an exclusive advisory lock on a sidecar file
/// derived from one instance's owner token, held from before its first row
/// is journaled until the store closes, and released by the OS if the
/// process dies first. Reconciliation judges a foreign row's owner live by
/// try-locking THAT owner's file (never its own, and never converting a
/// lock it holds), so a crashed owner's rows surface even while other
/// siblings stay live. Liveness is the held lock, never the file's
/// existence: the file itself is only hygiene.
pub(crate) struct OwnerLivenessMark {
    /// Held for the advisory lock alone; never read or written.
    _lock: std::fs::File,
    /// Path of the mark, kept to remove the file on a clean close.
    path: std::path::PathBuf,
}

impl OwnerLivenessMark {
    pub(crate) fn new(lock: std::fs::File, path: std::path::PathBuf) -> Self {
        Self { _lock: lock, path }
    }
}

impl Drop for OwnerLivenessMark {
    fn drop(&mut self) {
        // A clean close removes the file so store opens do not accumulate
        // one sidecar file each. A crash skips this and the reconcile pass
        // that claims the crashed owner's rows removes it instead; a
        // leftover is inert either way, because probes take liveness from
        // the lock, which dies with this descriptor. Tokens are never
        // reused, so no prober can confuse a successor file with this
        // owner.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Open a sidecar advisory-lock file, creating it if absent. Never
/// truncates: the file carries no contents, only its locks.
pub(crate) fn open_sidecar_lock_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// One foreign owner's liveness as read by a reconcile pass.
enum OwnerLiveness {
    /// The owner's mark was acquired, so the owner is gone and its rows are
    /// claimable. Holds the acquired lock (and the mark's path) until the
    /// claim lands and the stale file is removed.
    Gone {
        mark: std::fs::File,
        path: std::path::PathBuf,
    },
    /// The owner holds its mark: it is live and its rows defer to it.
    Live,
}

/// Probe whether the foreign owner named by `token` still lives, by trying
/// its per-owner mark non-blockingly. Runs only under the probe mutex, so
/// no two passes ever race one owner's mark or its cleanup, and only on
/// foreign tokens, so no pass ever touches a lock it itself holds.
///
/// The mark is opened with create: a live owner has held its lock since
/// before it journaled its first row, so an acquirable lock means the owner
/// is gone whether its file survived a crash or was already cleaned up.
/// This trusts the sidecar directory exactly as every other advisory lock
/// here does; deleting lock files out from under a live database breaks
/// their coordination as a whole, not just this probe.
fn probe_foreign_owner_liveness(
    database_path: &std::path::Path,
    token: &str,
) -> Result<OwnerLiveness, ReceiptStoreError> {
    let Some(path) = crate::sqlite_owner_mark_path(database_path, token) else {
        // Unreachable for a database that coordinates on sidecar files at
        // all; refuse the claim rather than guess.
        return Ok(OwnerLiveness::Live);
    };
    let mark = open_sidecar_lock_file(&path)?;
    match mark.try_lock() {
        Ok(()) => Ok(OwnerLiveness::Gone { mark, path }),
        Err(std::fs::TryLockError::WouldBlock) => Ok(OwnerLiveness::Live),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

/// Scope guard for the exclusive section of a reconcile pass: restores the
/// shared writer lifetime mark when dropped, so the downgrade happens on
/// every exit path, including a reconciler panic unwinding through the
/// pass. The mark descriptor outlives the pass (it lives on the store), so
/// a mark left exclusive would block every sibling open and defer every
/// sibling reconcile for the rest of this process's life. The normal path
/// consumes the guard through `downgrade` so a failed downgrade surfaces
/// as an error; the drop path downgrades best-effort because it only runs
/// while an unwind or an early error return is already in flight.
struct MarkDowngradeGuard<'lock> {
    /// The exclusively converted mark, or `None` while the pass has not
    /// converted it (or once it is downgraded).
    mark: Option<&'lock std::fs::File>,
}

impl MarkDowngradeGuard<'_> {
    /// Restore the shared mark now, surfacing the error the drop path
    /// would have to swallow. A no-op when the mark was never converted.
    fn downgrade(mut self) -> std::io::Result<()> {
        match self.mark.take() {
            Some(mark) => mark.lock_shared(),
            None => Ok(()),
        }
    }
}

impl Drop for MarkDowngradeGuard<'_> {
    fn drop(&mut self) {
        if let Some(mark) = self.mark.take() {
            // Cannot block: re-sharing waits only on a sibling's exclusive
            // conversion, and conversions happen only under the probe
            // mutex, which this pass still holds (the probe descriptor is
            // declared before this guard, so it is dropped after it).
            let _ = mark.lock_shared();
        }
    }
}
