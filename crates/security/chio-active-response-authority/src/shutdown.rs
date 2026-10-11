//! Explicit process signal ownership for the standalone authority daemon.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::{AuthorityError, Result};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_signal: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::Release);
}

/// Own SIGINT and SIGTERM for the remainder of this daemon process.
///
/// The handler works even when other threads existed before startup. Embedded
/// hosts should retain their own signal policy and pass their own stop flag to
/// `AuthorityDaemonRuntime::serve_until_stopped` instead. Installation never
/// clears a stop that was already requested.
#[allow(unsafe_code)]
#[allow(
    clippy::as_conversions,
    reason = "POSIX sigaction stores a C function address in sighandler_t."
)]
pub fn install_daemon_stop_handlers() -> Result<&'static AtomicBool> {
    // SAFETY: an all-zero sigaction is valid before its handler and mask are set.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_stop as *const () as libc::sighandler_t;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: sa_mask is a valid, writable sigset_t owned by this stack frame.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(AuthorityError::Runtime(
            "stop signal mask failed".to_owned(),
        ));
    }
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the C-ABI handler only writes a lock-free atomic; the initialized
        // action is installed only when this daemon owns the signal dispositions.
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(AuthorityError::Runtime(
                "stop signal handler failed".to_owned(),
            ));
        }
    }
    Ok(&STOP_REQUESTED)
}
