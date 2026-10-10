//! The wallet entitlement check reads the whole offers file on the blocking
//! pool behind its own non-queued lane, so a stalled offers file never holds
//! an async worker, and a request the lane refuses never reaches its upload.

use super::*;
use crate::trust_control::ingress_lanes::{IngressLane, WALLET_ENTITLEMENT_AT_CAPACITY};
use crate::trust_control::json_ingress::authenticate_wallet_credential;
use futures_util::FutureExt;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::AtomicBool;
use tokio::sync::mpsc::UnboundedReceiver;

/// How long a paused offers file withholds its bytes when nothing releases
/// them. It is shorter than `HANG_GUARD`, so a check that blocks the worker
/// surfaces as a failed progress assertion, never as the guard.
const PAUSE_BOUND: Duration = Duration::from_secs(10);

/// An offers file served through a FIFO. A check opens it and then waits for
/// the offers, which the test withholds until it releases them.
struct PausedOffers {
    path: PathBuf,
    release: std::sync::mpsc::Sender<()>,
    writer: Option<std::thread::JoinHandle<()>>,
}

impl PausedOffers {
    /// Serves one read of `offers` at `path`. A delivery on the returned
    /// receiver means a check has opened the file and waits for its bytes.
    fn serve(path: PathBuf, offers: Vec<u8>) -> TestResult<(Self, UnboundedReceiver<()>)> {
        let created = std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()?;
        if !created.success() {
            return Err("offers FIFO creation failed".into());
        }
        let (opened_tx, opened) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let fifo = path.clone();
        let writer = std::thread::spawn(move || {
            // Opening a FIFO for writing returns only once a reader opened it.
            let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&fifo) else {
                return;
            };
            let _ = opened_tx.send(());
            let _ = released.recv_timeout(PAUSE_BOUND);
            let _ = file.write_all(&offers);
        });
        Ok((
            Self {
                path,
                release,
                writer: Some(writer),
            },
            opened,
        ))
    }

    fn release(mut self) -> TestResult {
        self.release.send(())?;
        if let Some(writer) = self.writer.take() {
            writer.join().map_err(|_| "offers writer panicked")?;
        }
        Ok(())
    }
}

impl Drop for PausedOffers {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(writer) = self.writer.take() {
            // A writer still waiting for a reader is let through by one that
            // does not wait for a writer.
            let reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&self.path);
            let _ = writer.join();
            drop(reader);
        }
    }
}

/// Serves the fixture's offers through a FIFO beside its offers file and
/// returns the configuration that reads them from there.
fn paused_offers(
    fixture: &WalletFixture,
) -> TestResult<(PausedOffers, UnboundedReceiver<()>, TrustServiceConfig)> {
    let path = fixture
        .registry_path
        .with_file_name("paused-wallet-offers.json");
    let (offers, opened) =
        PausedOffers::serve(path.clone(), std::fs::read(&fixture.registry_path)?)?;
    let mut config = fixture.state.config.clone();
    config.passport_issuance_offers_file = Some(path);
    Ok((offers, opened, config))
}

fn bearer(token: &str) -> TestResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    Ok(headers)
}

#[tokio::test(flavor = "current_thread")]
async fn wallet_entitlement_leaves_the_async_worker_free_while_its_offers_file_is_paused(
) -> TestResult {
    let mut fixture = WalletFixture::live()?;
    let (offers, mut opened, config) = paused_offers(&fixture)?;
    fixture.state.config = config;
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&polls);
    let stream = futures_util::stream::once(async move {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
            br#"{"ignored":1,"ignored":2}"#,
        ))
    });
    let request = Request::builder()
        .method("POST")
        .uri(PASSPORT_ISSUANCE_CREDENTIAL_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", fixture.token))
        .body(Body::from_stream(stream))?;
    let router = super::super::super::super::build_router(fixture.state.clone());

    let answered = Arc::new(AtomicBool::new(false));
    let upload = tokio::spawn({
        let answered = Arc::clone(&answered);
        async move {
            let response = router.oneshot(request).await;
            answered.store(true, Ordering::SeqCst);
            response
        }
    });
    // A second task on this single worker observes the paused check while
    // the request is still outstanding only if the check yields the worker.
    let (progress_tx, progress_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let paused_in_read = opened.recv().await.is_some();
        let _ = progress_tx.send(paused_in_read && !answered.load(Ordering::SeqCst));
    });

    let progressed_while_outstanding = tokio::time::timeout(HANG_GUARD, progress_rx).await??;
    assert!(
        progressed_while_outstanding,
        "a task on the authenticating worker made no progress until the wallet entitlement check ended"
    );

    offers.release()?;
    let response = tokio::time::timeout(HANG_GUARD, upload).await???;
    // The entitled token passes, and the upload keeps its original-byte
    // validation.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert!(
        !fixture.seed_path.exists(),
        "pre-body authorization created signing material"
    );
    Ok(())
}

/// Starts a check of the fixture's live token on `lane`, a one-permit lane,
/// and returns once it is paused inside its offers file read, holding that
/// permit.
async fn held_check(
    fixture: &WalletFixture,
    lane: &IngressLane,
) -> TestResult<(PausedOffers, tokio::task::JoinHandle<Result<(), Response>>)> {
    let (offers, mut opened, config) = paused_offers(fixture)?;
    let headers = bearer(&fixture.token)?;
    let held = tokio::spawn({
        let lane = lane.clone();
        let clock = Arc::clone(&fixture.state.finding_challenge_clock);
        async move { authenticate_wallet_credential(&headers, config, clock, &lane).await }
    });
    tokio::time::timeout(HANG_GUARD, opened.recv())
        .await?
        .ok_or("the offers writer ended before a check opened the file")?;
    assert_eq!(lane.blocking_lane().available_permits(), 0);
    Ok((offers, held))
}

/// Polls one more check on `lane` exactly once and returns its refusal. A
/// check that would wait for admission is not ready and fails the test, and
/// so does one that lets the request through.
fn refused_check_polled_once(
    fixture: &WalletFixture,
    headers: &HeaderMap,
    lane: &IngressLane,
) -> TestResult<Response> {
    let decision = authenticate_wallet_credential(
        headers,
        fixture.state.config.clone(),
        Arc::clone(&fixture.state.finding_challenge_clock),
        lane,
    )
    .now_or_never()
    .ok_or("a check beyond the lane waited for admission")?;
    match decision {
        Err(refusal) => Ok(refusal),
        Ok(()) => Err("a check beyond the lane let its request through".into()),
    }
}

fn at_capacity() -> Response {
    plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        WALLET_ENTITLEMENT_AT_CAPACITY,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn next_wallet_entitlement_check_is_refused_at_once_while_a_paused_one_holds_the_permit(
) -> TestResult {
    let fixture = WalletFixture::live()?;
    let lane = IngressLane::wallet_entitlement(1);
    let (offers, held) = held_check(&fixture, &lane).await?;

    let refused = refused_check_polled_once(&fixture, &bearer(&fixture.token)?, &lane)?;
    assert_same_response(refused, at_capacity()).await?;
    // A missing bearer token is refused before admission, with the
    // unchanged challenge, even while the lane is full.
    let missing = refused_check_polled_once(&fixture, &HeaderMap::new(), &lane)?;
    assert_eq!(
        missing.headers().get(WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static(
            "Bearer realm=\"chio-passport-issuance\""
        ))
    );
    assert_same_response(
        missing,
        plain_http_error(
            StatusCode::UNAUTHORIZED,
            "missing or invalid issuance bearer token",
        ),
    )
    .await?;

    offers.release()?;
    let decision = tokio::time::timeout(HANG_GUARD, held).await??;
    assert!(
        matches!(decision, Ok(())),
        "the held check refused an entitled token"
    );
    assert_eq!(lane.blocking_lane().available_permits(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_wallet_entitlement_check_keeps_its_permit_until_the_check_ends() -> TestResult {
    let fixture = WalletFixture::live()?;
    let lane = IngressLane::wallet_entitlement(1);
    let (offers, held) = held_check(&fixture, &lane).await?;

    held.abort();
    let cancelled = tokio::time::timeout(HANG_GUARD, held)
        .await?
        .err()
        .ok_or("the aborted check still decided")?;
    assert!(cancelled.is_cancelled());
    assert_eq!(lane.blocking_lane().available_permits(), 0);
    let refused = refused_check_polled_once(&fixture, &bearer(&fixture.token)?, &lane)?;
    assert_same_response(refused, at_capacity()).await?;

    // The dropped request's check still reads the released offers, and only
    // then returns its permit.
    offers.release()?;
    tokio::time::timeout(HANG_GUARD, lane.blocking_lane().wait_for_free_permit()).await?;
    assert_eq!(lane.blocking_lane().available_permits(), 1);
    Ok(())
}

const HANG_GUARD: Duration = Duration::from_secs(30);

async fn assert_same_response(actual: Response, expected: Response) -> TestResult {
    assert_eq!(actual.status(), expected.status());
    assert_eq!(
        actual.headers().get(CONTENT_TYPE),
        expected.headers().get(CONTENT_TYPE)
    );
    let actual = axum::body::to_bytes(actual.into_body(), 4096).await?;
    let expected = axum::body::to_bytes(expected.into_body(), 4096).await?;
    assert_eq!(actual, expected);
    Ok(())
}

/// Service clones share the fixed four-permit wallet lane. Constructing an
/// independent service gives it fresh admission, even when the first is full.
#[tokio::test(flavor = "current_thread")]
async fn wallet_clones_share_admission_and_independent_service_states_remain_readable() -> TestResult
{
    let first = WalletFixture::live()?;
    let lane = first.state.wallet_entitlement_lane.clone();
    let mut fixtures = Vec::new();
    let mut held = Vec::new();
    for _ in 0..4 {
        let fixture = WalletFixture::live()?;
        let (offers, mut opened, config) = paused_offers(&fixture)?;
        let headers = bearer(&fixture.token)?;
        let check = tokio::spawn({
            let lane = lane.clone();
            let clock = Arc::clone(&fixture.state.finding_challenge_clock);
            async move { authenticate_wallet_credential(&headers, config, clock, &lane).await }
        });
        tokio::time::timeout(HANG_GUARD, opened.recv())
            .await?
            .ok_or("wallet read did not enter its pause")?;
        held.push((offers, check));
        fixtures.push(fixture);
    }
    assert_eq!(
        first
            .state
            .wallet_entitlement_lane
            .blocking_lane()
            .available_permits(),
        0
    );
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
    let response = super::super::super::super::build_router(first.state.clone())
        .oneshot(request)
        .await?;
    assert_same_response(response, at_capacity()).await?;
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let independent = WalletFixture::live()?;
    assert_eq!(
        independent
            .state
            .wallet_entitlement_lane
            .blocking_lane()
            .available_permits(),
        4
    );
    independent
        .submit(
            Some("Bearer unentitled-wallet"),
            StatusCode::UNAUTHORIZED,
            0,
        )
        .await?;
    for (offers, check) in held {
        offers.release()?;
        tokio::time::timeout(HANG_GUARD, check)
            .await??
            .map_err(|_| "entitled wallet check refused")?;
    }
    assert_eq!(lane.blocking_lane().available_permits(), 4);
    first
        .submit(
            Some("Bearer unentitled-wallet"),
            StatusCode::UNAUTHORIZED,
            0,
        )
        .await?;
    drop(fixtures);
    Ok(())
}
