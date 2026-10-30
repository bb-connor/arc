//! A safety stop cannot depend on successful authority-time acquisition.
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};

struct FaultClock(AtomicUsize);
impl Clock for FaultClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let (wall, monotonic) = match self.0.load(AtomicOrdering::SeqCst) {
            0 => (1_800_000_000_000, 1),
            1 => return Err(ClockError::Unavailable),
            2 => (1_799_999_999_999, 2),
            _ => (1_800_000_000_000, 0),
        };
        Ok(ClockReading::new(
            UnixMillis::new(wall),
            MonotonicInstant::from_nanos(monotonic),
        ))
    }
}

#[test]
fn clock_failure_during_emergency_stop_cannot_resume_execution() {
    for (mode, expected) in [
        (1, ClockError::Unavailable),
        (2, ClockError::WallClockRegression),
        (3, ClockError::MonotonicRegression),
    ] {
        let clock = Arc::new(FaultClock(AtomicUsize::new(0)));
        let mut kernel = ChioKernel::new_with_clock(make_config(), clock.clone());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
        let agent = make_keypair();
        let cap = make_capability(
            &kernel,
            &agent,
            make_scope(vec![make_grant("srv-a", "read_file")]),
            300,
        );
        let request = make_request("before-clock-fault", &cap, "read_file", "srv-a");
        assert_eq!(
            kernel
                .evaluate_tool_call_blocking(&request)
                .unwrap()
                .verdict,
            Verdict::Allow
        );
        clock.0.store(mode, AtomicOrdering::SeqCst);
        assert!(
            matches!(kernel.emergency_stop("clock incident"), Err(KernelError::Clock(error)) if error == expected)
        );
        assert!(
            kernel.is_emergency_stopped(),
            "time acquisition failure must still latch the safety stop"
        );
        assert_eq!(kernel.emergency_stopped_since(), None);
        assert_eq!(
            kernel.emergency_stop_reason().as_deref(),
            Some("clock incident")
        );
        clock.0.store(0, AtomicOrdering::SeqCst);
        let stopped = make_request("after-clock-recovery", &cap, "read_file", "srv-a");
        let denied = kernel.evaluate_tool_call_blocking(&stopped).unwrap();
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(denied.reason.as_deref(), Some(EMERGENCY_STOP_DENY_REASON));
        assert!(denied.receipt.verify_integrity_embedded_key().unwrap());
        kernel.emergency_resume().unwrap();
        let resumed = make_request("explicitly-resumed", &cap, "read_file", "srv-a");
        assert_eq!(
            kernel
                .evaluate_tool_call_blocking(&resumed)
                .unwrap()
                .verdict,
            Verdict::Allow
        );
    }
}

/// A clock that records whether the stop was already published when it was read.
struct ObservingClock {
    heads: std::sync::OnceLock<Arc<crate::stop::StopHeads>>,
    stopped_at_read: std::sync::Mutex<Vec<bool>>,
}

impl Clock for ObservingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if let Some(heads) = self.heads.get() {
            self.stopped_at_read
                .lock()
                .map_err(|_| ClockError::Unavailable)?
                .push(heads.is_stopped());
        }
        Ok(ClockReading::new(
            UnixMillis::new(1_800_000_000_000),
            MonotonicInstant::from_nanos(1),
        ))
    }
}

#[test]
fn emergency_stop_is_published_before_authority_time_is_read() {
    let clock = Arc::new(ObservingClock {
        heads: std::sync::OnceLock::new(),
        stopped_at_read: std::sync::Mutex::new(Vec::new()),
    });
    let kernel = ChioKernel::new_with_clock(make_config(), clock.clone());
    assert!(clock
        .heads
        .set(kernel.stop_control().heads().clone())
        .is_ok());

    kernel.emergency_stop("ordering").unwrap();

    let observed = clock.stopped_at_read.lock().unwrap().clone();
    assert!(!observed.is_empty(), "the stop must read authority time");
    assert!(
        observed.iter().all(|stopped| *stopped),
        "every authority-time read must observe the published stop"
    );
    assert_eq!(kernel.emergency_stopped_since(), Some(1_800_000_000));
}
