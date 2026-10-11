//! The pre-body wallet entitlement read must leave the async worker available.
use super::*;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const HANG_GUARD: Duration = Duration::from_secs(30);
const PAUSE_BOUND: Duration = Duration::from_secs(10);

struct PausedRegistry {
    path: std::path::PathBuf,
    release: std::sync::mpsc::Sender<()>,
    writer: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    finished: Arc<AtomicBool>,
}

impl PausedRegistry {
    fn serve(path: std::path::PathBuf) -> TestResult<(Self, tokio::sync::oneshot::Receiver<()>)> {
        std::fs::remove_file(&path)?;
        let created = std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()?;
        assert!(created.success(), "wallet registry FIFO creation failed");
        let bytes = canonical_json_bytes(&PassportIssuanceOfferRegistry::default())?;
        let (opened_tx, opened) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let completion = Arc::clone(&finished);
        let fifo = path.clone();
        let writer = std::thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new().write(true).open(&fifo)?;
            let _ = opened_tx.send(());
            // The bound releases a synchronously blocked Original, allowing
            // its progress assertion to fail instead of hanging the process.
            let _ = released.recv_timeout(PAUSE_BOUND);
            completion.store(true, Ordering::SeqCst);
            file.write_all(&bytes)
        });
        Ok((
            Self {
                path,
                release,
                writer: Some(writer),
                finished,
            },
            opened,
        ))
    }

    fn finish(mut self) -> TestResult {
        let _ = self.release.send(());
        if let Some(writer) = self.writer.take() {
            writer
                .join()
                .map_err(|_| "wallet registry writer panicked")??;
        }
        Ok(())
    }
}

impl Drop for PausedRegistry {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(writer) = self.writer.take() {
            // Also release a writer whose request was refused before opening.
            let reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&self.path);
            let _ = writer.join();
            drop(reader);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn wallet_ingress_registry_read_leaves_the_async_worker_available() -> TestResult {
    let fixture = WalletFixture::live()?;
    let (paused, opened) = PausedRegistry::serve(fixture.registry_path.clone())?;
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
    tokio::time::timeout(HANG_GUARD, opened).await??;
    let worker_progressed_while_read_paused = !paused.finished.load(Ordering::SeqCst);
    paused.finish()?;
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
