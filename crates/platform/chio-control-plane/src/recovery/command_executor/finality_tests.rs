//! Reserved native capacity retains the same affine work and worker lifecycle.
use super::*;
use std::{error::Error, time::Duration};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
type Reply = oneshot::Receiver<Result<(), RecoveryRuntimeError>>;

async fn pool(domain: ExecutionDomain) -> TestResult<CommandExecutor> {
    let executor = CommandExecutor::new_in_domain(domain);
    tokio::time::timeout(Duration::from_secs(2), executor.ready()).await??;
    Ok(executor)
}

async fn held_job(
    executor: &CommandExecutor,
    principal: &str,
) -> TestResult<(oneshot::Sender<()>, Reply)> {
    let (release, pending) = oneshot::channel();
    let (entered, started) = oneshot::channel();
    let response = executor.try_submit(principal.to_owned(), None, async move {
        let _ = entered.send(());
        pending
            .await
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        Ok(())
    })?;
    tokio::time::timeout(Duration::from_secs(2), started).await??;
    Ok((release, response))
}

async fn drain(jobs: Vec<(oneshot::Sender<()>, Reply)>) -> TestResult {
    let mut replies = Vec::new();
    for (release, reply) in jobs {
        let _ = release.send(());
        replies.push(reply);
    }
    for reply in replies {
        tokio::time::timeout(Duration::from_secs(2), reply).await???;
    }
    Ok(())
}

async fn idle(executor: &CommandExecutor, capacity: usize) -> TestResult {
    // Observe complete affine cleanup without extending a deadline or sleeping
    // a worker. A received result already follows this cleanup boundary.
    tokio::time::timeout(Duration::from_secs(2), async {
        while executor.capacity.available_permits() != capacity {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(executor
        .principals
        .lock()
        .map_err(|_| "principal map poisoned")?
        .is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_native_saturation_keeps_four_command_jobs_available() -> TestResult {
    let finality = pool(ExecutionDomain::ProviderFinality).await?;
    let commands = pool(ExecutionDomain::Command).await?;
    let mut finality_jobs = Vec::new();
    for principal in ["checked:first", "checked:second"] {
        finality_jobs.push(held_job(&finality, principal).await?);
    }
    let refused_finality = finality.try_submit("checked:third".into(), None, async { Ok(()) });
    let mut command_jobs = Vec::new();
    for principal in [
        "checked:first",
        "checked:first",
        "checked:second",
        "checked:second",
    ] {
        command_jobs.push(held_job(&commands, principal).await?);
    }
    let refused_command = commands.try_submit("checked:third".into(), None, async { Ok(()) });
    // The six admitted jobs have all started and remain pending in distinct
    // native domains. Neither caller nor global/principal capacity is shared.
    assert_eq!(finality.capacity.available_permits(), 0);
    assert_eq!(commands.capacity.available_permits(), 0);
    drain(command_jobs).await?;
    drain(finality_jobs).await?;
    assert!(matches!(
        refused_finality,
        Err(RecoveryRuntimeError::Unavailable)
    ));
    assert!(matches!(
        refused_command,
        Err(RecoveryRuntimeError::Unavailable)
    ));
    idle(&commands, 4).await?;
    idle(&finality, 2).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_finality_principal_preserves_another_principals_slot() -> TestResult {
    let executor = pool(ExecutionDomain::ProviderFinality).await?;
    let first = held_job(&executor, "checked:first").await?;
    let (release_duplicate, duplicate_pending) = oneshot::channel();
    let duplicate = executor.try_submit("checked:first".into(), None, async move {
        duplicate_pending
            .await
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        Ok(())
    });
    let other = executor.try_submit("checked:other".into(), None, async { Ok(73) });
    drop(release_duplicate);
    drain(vec![first]).await?;
    let duplicate_refused = matches!(duplicate, Err(RecoveryRuntimeError::Unavailable));
    if let Ok(accepted) = duplicate {
        let _ = tokio::time::timeout(Duration::from_secs(2), accepted).await??;
    }
    assert!(
        duplicate_refused,
        "one finality principal occupied the other reserved slot"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), other?).await???,
        73
    );
    idle(&executor, 2).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn saturated_finality_refusals_do_not_retain_idle_principals() -> TestResult {
    let executor = pool(ExecutionDomain::ProviderFinality).await?;
    let first = held_job(&executor, "checked:first").await?;
    let second = held_job(&executor, "checked:second").await?;
    for index in 0..64 {
        assert!(matches!(
            executor.try_submit(format!("checked:refused:{index}"), None, async { Ok(()) }),
            Err(RecoveryRuntimeError::Unavailable),
        ));
    }
    assert_eq!(
        executor
            .principals
            .lock()
            .map_err(|_| "principal map poisoned")?
            .len(),
        2
    );
    drain(vec![first, second]).await?;
    idle(&executor, 2).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn disconnected_finality_jobs_drain_after_executor_shutdown() -> TestResult {
    let executor = pool(ExecutionDomain::ProviderFinality).await?;
    let capacity = executor.capacity.clone();
    let principals = executor.principals.clone();
    let mut observed = executor.state.clone();
    let (completed, mut completions) = tokio::sync::mpsc::channel(2);
    let mut releases = Vec::new();
    for principal in ["checked:first", "checked:second"] {
        let (release, pending) = oneshot::channel();
        let (entered, started) = oneshot::channel();
        let completed = completed.clone();
        let response = executor.try_submit(principal.into(), None, async move {
            let _ = entered.send(());
            pending
                .await
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
            completed
                .try_send(())
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
            Ok(())
        })?;
        tokio::time::timeout(Duration::from_secs(2), started).await??;
        // Accepted work keeps its capacity when its response driver disconnects.
        drop(response);
        releases.push(release);
    }
    drop(completed);
    drop(executor);
    assert_eq!(capacity.available_permits(), 0);
    for release in releases {
        release
            .send(())
            .map_err(|_| "owned finality work was cancelled by shutdown")?;
    }
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(2), completions.recv())
            .await?
            .ok_or("accepted finality work did not complete")?;
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(2), completions.recv())
            .await?
            .is_none()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if observed.borrow().exited == 2 {
                return Ok::<_, RecoveryRuntimeError>(());
            }
            observed
                .changed()
                .await
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        }
    })
    .await??;
    assert_eq!(capacity.available_permits(), 2);
    assert!(principals
        .lock()
        .map_err(|_| "principal map poisoned")?
        .is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn contained_finality_panic_preserves_the_remaining_worker_capacity() -> TestResult {
    let executor = pool(ExecutionDomain::ProviderFinality).await?;
    let held = held_job(&executor, "checked:held").await?;
    let panicked = executor.try_submit::<()>("checked:panicked".into(), None, async {
        panic!("controlled native finality panic");
    })?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), panicked).await??,
        Err(RecoveryRuntimeError::Unavailable)
    );
    // The other worker is still held. A replacement can finish only if the
    // panicking worker and its exact principal/global permits survive cleanup.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if executor.capacity.available_permits() == 1 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let replacement = executor.try_submit("checked:panicked".into(), None, async { Ok(19) })?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), replacement).await???,
        19
    );
    drain(vec![held]).await?;
    idle(&executor, 2).await?;
    Ok(())
}
