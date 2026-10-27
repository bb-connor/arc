//! The pre-body wallet entitlement read must leave the async worker available.
use super::*;
use std::time::Duration;

const HANG_GUARD: Duration = Duration::from_secs(30);
const PAUSE_BOUND: Duration = Duration::from_secs(10);

struct PausedRegistry(crate::signed_input::read_pause::ReadPause);

impl PausedRegistry {
    fn serve(
        path: std::path::PathBuf,
    ) -> TestResult<(Self, tokio::sync::mpsc::UnboundedReceiver<()>)> {
        let bytes = canonical_json_bytes(&PassportIssuanceOfferRegistry::default())?;
        std::fs::write(&path, bytes)?;
        let (pause, opened) =
            crate::signed_input::read_pause::ReadPause::install(&path, PAUSE_BOUND);
        Ok((Self(pause), opened))
    }

    fn finish(self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn wallet_ingress_registry_read_leaves_the_async_worker_available() -> TestResult {
    let fixture = WalletFixture::live()?;
    let (paused, mut opened) = PausedRegistry::serve(fixture.registry_path.clone())?;
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&polls);
    let stream = futures_util::stream::once(async move {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{}"))
    });
    let request = Request::builder()
        .method("POST")
        .uri(PASSPORT_ISSUANCE_CREDENTIAL_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer unentitled-wallet")
        .body(Body::from_stream(stream))?;
    let router = super::super::super::super::build_router(fixture.state.clone());
    let task = tokio::spawn(async move { router.oneshot(request).await });
    tokio::time::timeout(HANG_GUARD, opened.recv())
        .await?
        .ok_or("registry read did not enter pause")?;
    let worker_progressed_while_read_paused = !paused.0.is_finished();
    paused.finish();
    let response = tokio::time::timeout(HANG_GUARD, task).await???;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert!(!fixture.seed_path.exists());
    assert!(
        worker_progressed_while_read_paused,
        "wallet ingress blocked the async worker until registry IO ended"
    );
    Ok(())
}
