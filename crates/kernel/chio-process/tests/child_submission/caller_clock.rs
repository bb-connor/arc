//! Caller clocks must remain consistent across independent process registries.
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct TestClock {
    millis: AtomicU64,
    unavailable: AtomicBool,
}
impl Clock for TestClock {
    fn read(&self) -> std::result::Result<ClockReading, ClockError> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(ClockError::Unavailable)
        } else {
            FixedClock::from_millis(self.millis.load(Ordering::SeqCst)).read()
        }
    }
}

async fn check(epoch: u64) -> Result {
    let directory = tempfile::tempdir()?;
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let clock = Arc::new(TestClock {
        millis: AtomicU64::new(epoch),
        unavailable: AtomicBool::new(false),
    });
    let kernel = support::kernel_with_clock(
        directory.path(),
        Box::new(Probe(contexts.clone())),
        clock.clone(),
    )?;
    let path = directory.path().join("process.db");
    let runtime = ProcessRuntime::open(&path, kernel.clone())?;
    let token = support::root(&runtime, &kernel, 5)?;
    let request = runtime.tool_request("root", "admitted", "tools", "read", json!({}))?;
    assert_eq!(
        runtime.invoke("root", "admitted", &request).await?.verdict,
        Verdict::Allow
    );
    let context = contexts
        .lock()
        .map_err(|_| "poisoned")?
        .first()
        .cloned()
        .ok_or("missing context")?;
    let registries = [runtime.registry(), ProcessRegistry::open(path, &kernel)?];
    for registry in &registries {
        assert_eq!(registry.caller(&context)?.id, "root");
        // The transaction-local caller checks must use the same clock too.
        assert!(matches!(
            registry.wait_for_children(&context, &["missing".into()], |_, _| Ok(())),
            Err(ProcessError::NotFound(_))
        ));
        let attempted = AtomicBool::new(false);
        registry.provision_signers(&[("root".into(), &support::parent_key())])?;
        let result = registry.submit_child(
            ChildSubmission {
                context: &context,
                template: "read",
                input: &json!({}),
                budget_share_bps: 1000,
                max_submissions: 2,
            },
            |_, _, _| {
                attempted.store(true, Ordering::SeqCst);
                Err(ProcessError::Invalid("issuance probe"))
            },
        );
        assert!(attempted.load(Ordering::SeqCst));
        assert!(matches!(
            result,
            Err(ProcessError::Invalid("issuance probe"))
        ));
        assert!(registry.child_work()?.is_empty());
    }
    clock.unavailable.store(true, Ordering::SeqCst);
    for registry in &registries {
        assert!(matches!(
            registry.caller(&context),
            Err(ProcessError::Kernel(KernelError::Clock(
                ClockError::Unavailable
            )))
        ));
    }
    clock.unavailable.store(false, Ordering::SeqCst);
    clock
        .millis
        .store(token.expires_at * 1000, Ordering::SeqCst);
    for registry in &registries {
        assert!(matches!(
            registry.caller(&context),
            Err(ProcessError::Unauthenticated)
        ));
    }
    clock.millis.store(epoch, Ordering::SeqCst);
    assert!(matches!(
        registries[0].caller(&context),
        Err(ProcessError::Kernel(KernelError::Clock(
            ClockError::WallClockRegression
        )))
    ));
    Ok(())
}

#[tokio::test]
async fn admitted_process_caller_uses_authority_epoch_before_machine_clock() -> Result {
    check(3_600_000).await
}

#[tokio::test]
async fn admitted_process_caller_uses_authority_epoch_after_machine_clock() -> Result {
    check(4_102_444_800_000).await
}
