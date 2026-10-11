//! A share snapshot samples physical time only after the mutation owner releases.

use super::*;
use crate::admission_operation::AdmissionMutationSequencer;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn caller_share_snapshot_waits_for_mutations_before_sampling_time(
) -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, _, store, invocations) = durable_admission_fixture("snapshot-sequence");
    let fence = store
        .fence
        .lock()
        .map_err(|_| "fixture fence poisoned")?
        .clone();
    let sequencer = AdmissionMutationSequencer::for_fence(&fence)?;
    let held = sequencer.lock()?;
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let waiter = scope.spawn(|| {
            let _ = started_tx.send(());
            finished_tx
                .send(kernel.load_durable_caller_budget_shares("test-parent"))
                .is_ok()
        });
        started_rx.recv_timeout(Duration::from_secs(2))?;
        let premature = finished_rx.recv_timeout(Duration::from_millis(50));
        let released_at = current_unix_timestamp_ms();
        drop(held);
        let (early, result) = match premature {
            Ok(result) => (true, result),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                (false, finished_rx.recv_timeout(Duration::from_secs(2))?)
            }
            Err(error) => return Err(error.into()),
        };
        assert!(waiter.join().map_err(|_| "snapshot worker panicked")?);
        assert!(
            !early,
            "share snapshot reached the store while a mutation was still owned"
        );
        assert!(
            result.is_err_and(|error| error.contains("sibling-share accounting is unsupported"))
        );
        let times = store
            .caller_share_times
            .lock()
            .map_err(|_| "fixture snapshot lock poisoned")?;
        assert_eq!(times.len(), 1);
        assert!(
            times[0] >= released_at,
            "snapshot retained its pre-lock timestamp"
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(store
            .state
            .lock()
            .map_err(|_| "fixture state poisoned")?
            .operation
            .is_none());
        Ok(())
    })
}
