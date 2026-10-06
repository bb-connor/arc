//! Lifetime trace supervision of a launched target, and the pidfd waits and
//! signals that observe and control the target alongside its tracer.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{ptrace_resume, CageLaunchError};
use crate::CageEnforcementFailureCode;

/// The traced target the supervisor keeps after a verified launch.
pub(super) struct TracedTarget {
    pub(super) process_id: u32,
    pub(super) pidfd: Arc<OwnedFd>,
}

enum TraceEvent {
    Stopped(i32),
    Exited,
    Gone,
    WaitFailed,
}

const SUPERVISOR_KILL_SETTLE: Duration = Duration::from_secs(5);

/// Delays before each retry of a failed pidfd kill. The attempt after the
/// last delay is final.
const SUPERVISOR_KILL_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(1),
    Duration::from_millis(10),
    Duration::from_millis(50),
];

/// Trace the target until it exits. The launch already consumed and verified
/// the one permitted exec, so a later exec event is killed at the stop,
/// before the new image runs an instruction. A signal-delivery stop resumes
/// with exactly its signal. A group stop is held with `PTRACE_LISTEN`, so
/// SIGSTOP and SIGCONT keep their ordinary meaning, and a `PTRACE_EVENT_STOP`
/// reporting SIGTRAP, which follows SIGCONT, resumes with no signal. Any other
/// event, or a failed ptrace request, is resolved by killing the target
/// through its pidfd; the exit is then observed, never assumed. Every wait
/// uses `WNOWAIT`, so reaping stays with the child handle. If the kill cannot
/// be delivered, the supervisor returns and its exit leaves the target to
/// `PTRACE_O_EXITKILL` and the parent-death signal.
pub(super) fn supervise_traced_target(traced: &TracedTarget) {
    let mut killed_at: Option<Instant> = None;
    loop {
        let status = match next_trace_event(&traced.pidfd) {
            TraceEvent::Stopped(status) => status,
            TraceEvent::Exited | TraceEvent::Gone => return,
            TraceEvent::WaitFailed => {
                let _ = kill_traced_target(&traced.pidfd);
                return;
            }
        };
        if let Some(killed) = killed_at {
            // A stop can still be reported while SIGKILL takes effect.
            if killed.elapsed() > SUPERVISOR_KILL_SETTLE {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        let event = (status >> 8) & 0xff;
        let signal = status & 0x7f;
        let handled = match event {
            0 => ptrace_resume(traced.process_id, signal, "signal_continue"),
            libc::PTRACE_EVENT_STOP if is_job_control_stop(signal) => {
                ptrace_listen(traced.process_id)
            }
            libc::PTRACE_EVENT_STOP => ptrace_resume(traced.process_id, 0, "event_stop_continue"),
            _ => Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::ExecEventMissing,
                "unexpected_trace_event",
            )),
        };
        if handled.is_err() {
            if !kill_traced_target(&traced.pidfd) {
                return;
            }
            killed_at = Some(Instant::now());
        }
    }
}

/// Deliver SIGKILL through the pidfd, retrying a failed request after each
/// bounded delay. Returns whether a request was accepted.
fn kill_traced_target(pidfd: &OwnedFd) -> bool {
    if kill_pidfd(pidfd).is_ok() {
        return true;
    }
    for delay in SUPERVISOR_KILL_RETRY_DELAYS {
        std::thread::sleep(delay);
        if kill_pidfd(pidfd).is_ok() {
            return true;
        }
    }
    false
}

const fn is_job_control_stop(signal: i32) -> bool {
    matches!(
        signal,
        libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
    )
}

fn next_trace_event(pidfd: &OwnedFd) -> TraceEvent {
    let Ok(id) = libc::id_t::try_from(pidfd.as_raw_fd()) else {
        return TraceEvent::WaitFailed;
    };
    loop {
        // SAFETY: siginfo_t is a plain kernel output structure.
        let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: information is writable and id names the retained pidfd.
        // WNOWAIT leaves every stop and exit for its owner.
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                id,
                &mut information,
                libc::WEXITED | libc::WSTOPPED | libc::WNOWAIT | libc::__WALL,
            )
        };
        if result == 0 {
            return match information.si_code {
                libc::CLD_TRAPPED | libc::CLD_STOPPED => {
                    // SAFETY: si_status is set for the CLD_* codes waitid
                    // reports. A ptrace stop reports `(event << 8) | signal`.
                    let status = unsafe { information.si_status() };
                    TraceEvent::Stopped(status)
                }
                libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED => TraceEvent::Exited,
                _ => TraceEvent::WaitFailed,
            };
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            return TraceEvent::Gone;
        }
        return TraceEvent::WaitFailed;
    }
}

fn ptrace_listen(process_id: u32) -> Result<(), CageLaunchError> {
    let pid = i32::try_from(process_id).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "process_id",
        )
    })?;
    // SAFETY: the seized target is in a group stop of this tracer; LISTEN
    // takes no address or data.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_LISTEN,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    } != 0
    {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::TraceHandshakeFailed,
            "group_stop_listen",
        ));
    }
    Ok(())
}

pub(in crate::launch) enum PidfdReap {
    Running,
    Exited(ExitStatus),
    ReapedWithoutStatus,
}

pub(in crate::launch) fn try_reap_pidfd(pidfd: &OwnedFd) -> Result<PidfdReap, CageLaunchError> {
    waitid_pidfd(pidfd, true)
}

pub(in crate::launch) fn reap_pidfd(pidfd: &OwnedFd) -> Result<PidfdReap, CageLaunchError> {
    waitid_pidfd(pidfd, false)
}

#[cfg(test)]
pub(in crate::launch) fn pidfd_is_reaped(pidfd: &OwnedFd) -> Result<bool, CageLaunchError> {
    let id = libc::id_t::try_from(pidfd.as_raw_fd()).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "pidfd_observe_id",
        )
    })?;
    loop {
        // SAFETY: siginfo_t is a plain kernel output structure. WNOWAIT
        // observes exact pidfd state without consuming a terminal status.
        let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: information is writable and id names the retained pidfd.
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                id,
                &mut information,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(true);
        }
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "pidfd_observe",
        ));
    }
}

fn waitid_pidfd(pidfd: &OwnedFd, nonblocking: bool) -> Result<PidfdReap, CageLaunchError> {
    let id = libc::id_t::try_from(pidfd.as_raw_fd()).map_err(|_| {
        CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "pidfd_wait_id",
        )
    })?;
    // While its supervisor traces the target, any thread of this process
    // that waits on it also sees its ptrace stops, whatever the flags. Each
    // wait therefore observes with WNOWAIT first: a stop belongs to the
    // supervisor and reads as still running, and only an observed exit is
    // then reaped, which no stop can precede.
    let mut observed_exit = false;
    loop {
        // SAFETY: siginfo_t is a plain kernel output structure.
        let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let options = if observed_exit {
            libc::WEXITED | libc::WNOHANG
        } else {
            libc::WEXITED | libc::WNOWAIT | if nonblocking { libc::WNOHANG } else { 0 }
        };
        // SAFETY: information is writable, id names the owned pidfd, and the
        // options request terminal child state for that exact child.
        let result = unsafe { libc::waitid(libc::P_PIDFD, id, &mut information, options) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(PidfdReap::ReapedWithoutStatus);
            }
            return Err(CageLaunchError::bootstrap_failed(
                CageEnforcementFailureCode::StatusProtocolViolation,
                "pidfd_wait",
            ));
        }
        // SAFETY: waitid initialized the SIGCHLD view of siginfo_t. A zero PID
        // is Linux's WNOHANG indication that the exact child is still live.
        let observed_pid = unsafe { information.si_pid() };
        if observed_pid == 0 {
            if nonblocking || observed_exit {
                return Ok(PidfdReap::Running);
            }
            continue;
        }
        if matches!(
            information.si_code,
            libc::CLD_TRAPPED | libc::CLD_STOPPED | libc::CLD_CONTINUED
        ) {
            if nonblocking {
                return Ok(PidfdReap::Running);
            }
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        if !observed_exit {
            observed_exit = true;
            continue;
        }
        // SAFETY: si_status is initialized for the CLD_* codes returned by
        // waitid with WEXITED.
        let observed_status = unsafe { information.si_status() };
        let raw_status = match information.si_code {
            libc::CLD_EXITED if (0..=255).contains(&observed_status) => observed_status << 8,
            libc::CLD_KILLED if (1..=127).contains(&observed_status) => observed_status,
            libc::CLD_DUMPED if (1..=127).contains(&observed_status) => observed_status | 0x80,
            _ => {
                return Err(CageLaunchError::bootstrap_failed(
                    CageEnforcementFailureCode::StatusProtocolViolation,
                    "pidfd_wait_status",
                ));
            }
        };
        return Ok(PidfdReap::Exited(ExitStatus::from_raw(raw_status)));
    }
}

pub(in crate::launch) fn signal_pidfd(pidfd: &OwnedFd, signal: i32) -> Result<(), CageLaunchError> {
    if !matches!(signal, libc::SIGHUP | libc::SIGINT | libc::SIGTERM) {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            "termination_signal",
        ));
    }
    send_pidfd_signal(pidfd, signal, "pidfd_signal")
}

pub(in crate::launch) fn kill_pidfd(pidfd: &OwnedFd) -> Result<(), CageLaunchError> {
    send_pidfd_signal(pidfd, libc::SIGKILL, "pidfd_kill")
}

fn send_pidfd_signal(
    pidfd: &OwnedFd,
    signal: i32,
    failure_stage: &'static str,
) -> Result<(), CageLaunchError> {
    // SAFETY: the pidfd is owned and the remaining arguments contain no
    // pointers. A zero flags value is required by the kernel ABI.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 {
        return Err(CageLaunchError::bootstrap_failed(
            CageEnforcementFailureCode::StatusProtocolViolation,
            failure_stage,
        ));
    }
    Ok(())
}
