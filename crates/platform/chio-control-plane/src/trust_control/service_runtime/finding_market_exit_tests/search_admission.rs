//! The public finding search runs on the blocking pool behind its own
//! non-queued lane, so a slow store read or authority-status resolution never
//! holds an async worker.
use super::*;
use crate::trust_control::finding_challenge_coordinator::FindingAuthorityStatusResolver;
use crate::trust_control::finding_search_routes::search_findings_in_lane;
use futures_util::FutureExt;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// Bounds every wait in this module.
const HANG_GUARD: Duration = Duration::from_secs(30);
/// How long the paused resolution holds when nothing releases it. It is
/// shorter than `HANG_GUARD`, so a search that blocks the worker surfaces as a
/// failed progress assertion, never as the guard.
const PAUSE_BOUND: Duration = Duration::from_secs(10);

/// The market's authority-status resolver, holding its first resolution until
/// the test releases it.
struct PausedAuthorityStatus {
    resolver: TestStatusOperatorAuthorityResolver,
    held: AtomicBool,
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    released: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl PausedAuthorityStatus {
    /// Each delivery on the returned receiver means a search is inside the
    /// held resolution; a send on the returned sender releases it.
    fn holding_first() -> (
        Arc<Self>,
        tokio::sync::mpsc::UnboundedReceiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered, entries) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = std::sync::mpsc::channel();
        let resolver = Self {
            resolver: TestStatusOperatorAuthorityResolver::default(),
            held: AtomicBool::new(false),
            entered,
            released: std::sync::Mutex::new(released),
        };
        (Arc::new(resolver), entries, release)
    }
}

impl FindingAuthorityStatusResolver for PausedAuthorityStatus {
    fn resolve(
        &self,
        pin: &FindingAuthorityPin,
        now: u64,
    ) -> Result<SignedFindingAuthorityStatus, String> {
        if !self.held.swap(true, Ordering::SeqCst) {
            let _ = self.entered.send(());
            if let Ok(released) = self.released.lock() {
                let _ = released.recv_timeout(PAUSE_BOUND);
            }
        }
        self.resolver.resolve(pin, now)
    }

    fn checkpoint_publication(
        &self,
        proof: &AnchorInclusionProof,
        now: u64,
    ) -> Result<SignedFindingAnchorCheckpointPublication, String> {
        self.resolver.checkpoint_publication(proof, now)
    }
}

fn context_query() -> FindingSearchQuery {
    FindingSearchQuery {
        context_sha256: Some(HEX64.to_string()),
        ..FindingSearchQuery::default()
    }
}

async fn found_finding_ids(response: Response) -> Result<Vec<String>, AnyError> {
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let value = json_body(&body)?;
    Ok(value["results"]
        .as_array()
        .ok_or_else(|| missing("search results array"))?
        .iter()
        .filter_map(|row| row["findingId"].as_str().map(str::to_owned))
        .collect())
}

/// A seeded market whose search resolves authority status through `resolver`.
async fn market_resolving_through(
    resolver: Arc<PausedAuthorityStatus>,
) -> Result<(MarketStack, TrustServiceState), AnyError> {
    let mut stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    stack.seed_market().await?;
    let mut state = stack.state.clone();
    state.finding_authority_status_resolver = Some(resolver);
    Ok((stack, state))
}

#[tokio::test(flavor = "current_thread")]
async fn finding_search_leaves_the_async_worker_free_while_its_authority_status_is_paused(
) -> TestResult {
    let (resolver, mut entered, release) = PausedAuthorityStatus::holding_first();
    let (stack, state) = market_resolving_through(resolver).await?;
    let search_finished = Arc::new(AtomicBool::new(false));
    let search = tokio::spawn({
        let search_finished = Arc::clone(&search_finished);
        async move {
            let response = handle_search_findings_get(State(state), Query(context_query())).await;
            search_finished.store(true, Ordering::SeqCst);
            response
        }
    });
    // A second task on the same single worker. It can observe the paused
    // resolution while the search is still outstanding only if the search
    // yields the worker instead of blocking it.
    let (progress_tx, progress_rx) = tokio::sync::oneshot::channel();
    let observed = Arc::clone(&search_finished);
    tokio::spawn(async move {
        let paused_in_search = entered.recv().await.is_some();
        let _ = progress_tx.send(paused_in_search && !observed.load(Ordering::SeqCst));
    });

    let progressed_while_outstanding = tokio::time::timeout(HANG_GUARD, progress_rx).await??;
    assert!(
        progressed_while_outstanding,
        "a task on the searching worker made no progress until the finding search ended"
    );

    release.send(())?;
    let response = tokio::time::timeout(HANG_GUARD, search).await??;
    assert_eq!(
        found_finding_ids(response).await?,
        vec![stack.web.finding_id.clone()]
    );
    Ok(())
}

const AT_CAPACITY: &str = "finding search is at capacity";

async fn assert_same_response(actual: Response, expected: Response) -> TestResult {
    assert_eq!(actual.status(), expected.status());
    assert_eq!(
        actual.headers().get(CONTENT_TYPE),
        expected.headers().get(CONTENT_TYPE)
    );
    let actual = axum::body::to_bytes(actual.into_body(), usize::MAX).await?;
    let expected = axum::body::to_bytes(expected.into_body(), usize::MAX).await?;
    assert_eq!(actual, expected);
    Ok(())
}

/// A search on a one-permit lane, paused inside its authority-status
/// resolution while it holds that permit.
struct HeldSearch {
    stack: MarketStack,
    state: TrustServiceState,
    lane: Arc<tokio::sync::Semaphore>,
    release: std::sync::mpsc::Sender<()>,
    search: tokio::task::JoinHandle<Response>,
}

impl HeldSearch {
    async fn start() -> Result<Self, AnyError> {
        let (resolver, mut entered, release) = PausedAuthorityStatus::holding_first();
        let (stack, state) = market_resolving_through(resolver).await?;
        let lane = Arc::new(tokio::sync::Semaphore::new(1));
        let search = tokio::spawn({
            let lane = Arc::clone(&lane);
            let state = state.clone();
            async move { search_findings_in_lane(&lane, state, context_query()).await }
        });
        tokio::time::timeout(HANG_GUARD, entered.recv())
            .await?
            .ok_or_else(|| missing("paused authority-status resolution"))?;
        assert_eq!(lane.available_permits(), 0);
        Ok(Self {
            stack,
            state,
            lane,
            release,
            search,
        })
    }
}

/// Polls one more search on `lane` exactly once. One that would wait for
/// admission is not ready and fails.
fn next_search_polled_once(
    lane: &Arc<tokio::sync::Semaphore>,
    state: &TrustServiceState,
) -> Result<Response, AnyError> {
    search_findings_in_lane(lane, state.clone(), context_query())
        .now_or_never()
        .ok_or_else(|| missing("an admission decision without waiting"))
}

#[tokio::test(flavor = "current_thread")]
async fn next_finding_search_is_refused_at_once_while_a_paused_one_holds_the_permit() -> TestResult
{
    let held = HeldSearch::start().await?;

    assert_same_response(
        next_search_polled_once(&held.lane, &held.state)?,
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await?;

    held.release.send(())?;
    let response = tokio::time::timeout(HANG_GUARD, held.search).await??;
    assert_eq!(
        found_finding_ids(response).await?,
        vec![held.stack.web.finding_id.clone()]
    );
    assert_eq!(held.lane.available_permits(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_finding_search_keeps_its_permit_until_the_search_ends() -> TestResult {
    let held = HeldSearch::start().await?;

    held.search.abort();
    let cancelled = match tokio::time::timeout(HANG_GUARD, held.search).await? {
        Ok(_) => return Err(missing("a cancelled search")),
        Err(error) => error,
    };
    assert!(cancelled.is_cancelled());
    assert_eq!(held.lane.available_permits(), 0);
    assert_same_response(
        next_search_polled_once(&held.lane, &held.state)?,
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await?;

    held.release.send(())?;
    let returned =
        tokio::time::timeout(HANG_GUARD, Arc::clone(&held.lane).acquire_owned()).await??;
    drop(returned);
    assert_eq!(held.lane.available_permits(), 1);
    Ok(())
}
