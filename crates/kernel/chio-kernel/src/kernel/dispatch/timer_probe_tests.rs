use super::dispatch_timer_available;

// The probe verdict is keyed by runtime id, so each runtime is probed under
// its own key. `re_probes_when_the_entered_runtime_changes_on_one_thread`
// exercises two runtimes on one thread directly; the two single-runtime tests
// below pin the per-runtime verdicts in isolation.

#[test]
fn re_probes_when_the_entered_runtime_changes_on_one_thread(
) -> Result<(), Box<dyn std::error::Error>> {
    // A timerless runtime, then a timer-enabled one, both entered from this
    // same OS thread. A per-thread-only cache would reuse the timerless
    // verdict and wrongly report no timer in the second runtime; keying on the
    // runtime id re-probes when the entered runtime changes.
    let timerless = tokio::runtime::Builder::new_current_thread().build()?;
    timerless.block_on(async {
        assert!(!dispatch_timer_available());
    });
    let timed = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    timed.block_on(async {
        assert!(dispatch_timer_available());
        let elapsed = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            std::future::pending::<()>(),
        )
        .await;
        assert!(elapsed.is_err(), "the timer must actually fire here");
    });
    Ok(())
}

#[test]
fn reports_false_in_a_runtime_without_a_time_driver() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        assert!(!dispatch_timer_available());
        // Mirror the hot-path guard: only wrap work in a timer when the probe
        // allows it, so a timerless runtime degrades to inline instead of
        // panicking on timer construction.
        let ran_inline = if dispatch_timer_available() {
            tokio::time::timeout(std::time::Duration::from_millis(1), std::future::ready(()))
                .await
                .is_ok()
        } else {
            std::future::ready(()).await;
            true
        };
        assert!(ran_inline);
    });
    Ok(())
}

#[test]
fn reports_true_in_a_runtime_with_a_time_driver() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        assert!(dispatch_timer_available());
        let elapsed = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            std::future::pending::<()>(),
        )
        .await;
        assert!(elapsed.is_err(), "the timer must actually fire here");
    });
    Ok(())
}
