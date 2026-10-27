//! Admission to registry writes never queues, and a write whose request is
//! dropped keeps its permit and the registry lock until the write ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::to_bytes;
use chio_credentials::PassportLifecycleState;

use super::*;
use crate::passport_verifier::test_fixtures::passport_issued_at;
use crate::passport_verifier::PassportStatusRegistry;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Bounds every wait in this module.
const HANG_GUARD: Duration = Duration::from_secs(30);

async fn error_of(
    response: Response,
) -> Result<(StatusCode, String), Box<dyn std::error::Error + Send + Sync>> {
    let status = response.status();
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    Ok((
        status,
        body["error"].as_str().unwrap_or_default().to_string(),
    ))
}

#[tokio::test]
async fn a_saturated_lane_refuses_at_once_and_runs_nothing() -> TestResult {
    let lane = BlockingLane::new("operator_registry_write", 1);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let held = tokio::spawn({
        let lane = lane.clone();
        async move {
            run_registry_update_in(&lane, move || {
                let _ = entered_tx.send(());
                let _ = release_rx.recv_timeout(HANG_GUARD);
                Ok::<(), RegistryUpdateError>(())
            })
            .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(HANG_GUARD)).await??;
    let ran = Arc::new(AtomicBool::new(false));
    let response = tokio::time::timeout(
        HANG_GUARD,
        run_registry_update_in(&lane, {
            let ran = Arc::clone(&ran);
            move || {
                ran.store(true, Ordering::SeqCst);
                Ok::<(), RegistryUpdateError>(())
            }
        }),
    )
    .await?;
    assert_eq!(
        error_of(response).await?,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "registry writes are at capacity; nothing was changed, retry".to_string()
        )
    );
    assert!(!ran.load(Ordering::SeqCst));

    release_tx.send(())?;
    assert_eq!(
        tokio::time::timeout(HANG_GUARD, held).await??.status(),
        StatusCode::OK
    );
    let response = run_registry_update_in(&lane, || Ok::<(), RegistryUpdateError>(())).await;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_write_keeps_its_permit_and_lock_until_the_write_ends() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let mut registry = PassportStatusRegistry::default();
    let record = registry
        .publish(
            &passport_issued_at(121, 1_730_000_000).map_err(|error| error.to_string())?,
            1_730_000_060,
            Default::default(),
        )
        .map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec(&registry)?;

    std::fs::write(&path, bytes)?;
    let (pause, mut opened) =
        crate::signed_input::read_pause::ReadPause::install(&path, HANG_GUARD);

    let lane = BlockingLane::new("operator_registry_write", 1);
    let request = tokio::spawn({
        let (lane, path, passport_id) = (lane.clone(), path.clone(), record.passport_id.clone());
        async move {
            run_registry_update_in(&lane, move || {
                PassportStatusRegistry::update(&path, |registry| {
                    registry.revoke(&passport_id, Some("compromised"), Some(1_730_000_065))
                })
            })
            .await
        }
    });
    tokio::time::timeout(HANG_GUARD, opened.recv())
        .await?
        .ok_or("registry read ended before entering the pause")?;

    request.abort();
    assert!(request
        .await
        .err()
        .is_some_and(|error| error.is_cancelled()));
    assert_eq!(lane.available_permits(), 0);
    assert!(matches!(
        crate::signed_input::lock_registry(&path),
        Err(RegistryUpdateError::Busy)
    ));

    pause.release();
    tokio::time::timeout(HANG_GUARD, lane.wait_for_free_permit()).await?;
    assert_eq!(lane.available_permits(), 1);

    let reopened = PassportStatusRegistry::load(&path)?;
    assert_eq!(
        reopened
            .get(&record.passport_id)
            .map(|record| record.status),
        Some(PassportLifecycleState::Revoked),
        "the write ran to completion after its request was dropped"
    );
    assert!(std::fs::symlink_metadata(&path)?.file_type().is_file());
    drop(crate::signed_input::lock_registry(&path).map_err(|error| error.to_string())?);
    Ok(())
}
