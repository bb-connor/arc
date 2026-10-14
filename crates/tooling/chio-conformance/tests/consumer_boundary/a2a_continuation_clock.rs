//! Preparation failures retain actual signed approval custody and retryability.

use super::a2a_v1::{call, lookup, send};
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, SystemClock};

struct OneShotClock {
    remaining: AtomicU64,
    armed_reads: AtomicU64,
}

impl Clock for OneShotClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let remaining =
            self.remaining
                .fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |remaining| match remaining {
                        u64::MAX => None,
                        0 => Some(u64::MAX),
                        value => Some(value - 1),
                    },
                );
        if remaining.is_ok() {
            self.armed_reads.fetch_add(1, Ordering::SeqCst);
        }
        if remaining == Ok(0) {
            return Err(ClockError::Unavailable);
        }
        SystemClock.read()
    }
}

#[test]
fn transient_deadline_clock_failure_preserves_the_original_task_for_retry() -> TestResult {
    let fixture = Fixture::new()?.with_threshold_approval()?;
    let clock = Arc::new(OneShotClock {
        remaining: AtomicU64::new(u64::MAX),
        armed_reads: AtomicU64::new(0),
    });
    let request = fixture.approval_request("v1-transient-deadline-clock")?;
    let mut consumer = fixture.open_with_clock(Protocol::A2a, clock.clone())?;
    let pending = call(&mut consumer, &request, send(&request, "application/json"))?;
    let task = &pending["result"]["task"];
    let id = task["id"].as_str().ok_or("pending task id")?;
    let proposal =
        serde_json::from_value(task["artifacts"][0]["parts"][0]["data"]["proposal"].clone())?;
    let approved = fixture.approved_request(&request, proposal)?;
    let mut wire = send(&approved, "application/json");
    wire["params"]["message"]["taskId"] = json!(id);
    // Continuation validation obtains a fresh sample. Its next deadline check
    // fails before orchestration, then the clock automatically recovers.
    clock.remaining.store(1, Ordering::SeqCst);
    let failed = call(&mut consumer, &approved, wire.clone())?;
    assert_eq!(failed["error"]["message"], ClockError::Unavailable.code());
    assert_eq!(clock.armed_reads.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let Frontend::A2a(kernel, _) = &consumer.frontend else {
        return Err("expected A2A consumer".into());
    };
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
    let observed = call(&mut consumer, &approved, lookup("GetTask", id))?;
    assert_eq!(
        observed["result"], *task,
        "a pre-evaluation clock failure must retain the original pending task"
    );
    let completed = call(&mut consumer, &approved, wire)?;
    assert_eq!(completed["result"]["task"]["id"], id);
    assert_eq!(completed["result"]["task"]["contextId"], task["contextId"]);
    assert_eq!(
        completed["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{completed}"
    );
    let receipt: ChioReceipt =
        serde_json::from_value(completed["result"]["task"]["metadata"]["chio"]["receipt"].clone())?;
    assert!(receipt.verify_signature()?);
    assert_eq!(receipt.kernel_key, fixture.signer.public_key());
    assert_eq!(
        receipt.decision,
        Some(chio_core::receipt::decision::Decision::Allow)
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
