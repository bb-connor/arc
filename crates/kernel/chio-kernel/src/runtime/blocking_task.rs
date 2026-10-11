/// Aborts an offloaded `spawn_blocking` task when the awaiting future is
/// dropped, whether because its deadline fired or because the caller was
/// cancelled. Dropping a bare `JoinHandle` only *detaches* the task: one still
/// queued on a saturated blocking pool would then start and run the tool call
/// (or guard) after the kernel has already emitted a timed-out response and
/// unwound its charges. Aborting cancels a not-yet-started task so it cannot
/// execute side effects past the deadline; a task already running its blocking
/// body cannot be interrupted, but its own inner deadline still frees it, and a
/// task that already finished is aborted as a harmless no-op.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
