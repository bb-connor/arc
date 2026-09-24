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
pub fn install_daemon_stop_handlers() -> Result<&'static AtomicBool> {
    // SAFETY: sigaction is initialized before use. The C ABI handler only
    // stores a lock-free AtomicBool; it never allocates, locks, or performs I/O.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = request_stop as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        if libc::sigemptyset(&mut action.sa_mask) != 0 {
            return Err(AuthorityError::Runtime(
                "stop signal mask failed".to_owned(),
            ));
        }
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(AuthorityError::Runtime(
                    "stop signal handler failed".to_owned(),
                ));
            }
        }
    }
    Ok(&STOP_REQUESTED)
}
