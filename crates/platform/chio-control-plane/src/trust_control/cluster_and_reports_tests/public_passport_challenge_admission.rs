//! A public holder submission is verified on the blocking pool behind its own
//! non-queued lane, so a slow challenge store or status registry read never
//! holds an async worker.
use super::*;
use chio_credentials::{
    build_agent_passport, create_passport_presentation_challenge_with_reference,
    issue_reputation_credential, respond_to_passport_presentation_challenge, AttestationWindow,
    ChioCredentialEvidence, PassportPresentationChallengeArgs, PassportPresentationOptions,
    PassportPresentationVerification,
};
use futures_util::FutureExt;
use std::sync::atomic::{AtomicBool, Ordering};

/// Bounds every wait in this module.
const HANG_GUARD: Duration = Duration::from_secs(30);
/// How long the status registry withholds its bytes when nothing releases
/// them. It is shorter than `HANG_GUARD`, so a verification that blocks the
/// worker surfaces as a failed progress assertion, never as the guard.
const PAUSE_BOUND: Duration = Duration::from_secs(10);
const SELF_URL: &str = "http://127.0.0.1:1";
const VERIFIER: &str = "https://verifier.example.test";

struct PausedStatusRegistry(crate::signed_input::read_pause::ReadPause);

impl PausedStatusRegistry {
    fn serve(path: PathBuf) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let registry = serde_json::to_vec(&PassportStatusRegistry::default()).test_unwrap();
        std::fs::write(&path, registry).test_unwrap();
        let (pause, opened) =
            crate::signed_input::read_pause::ReadPause::install(&path, PAUSE_BOUND).test_unwrap();
        (Self(pause), opened)
    }

    fn release(self) {
        self.0.release();
    }
}

/// A standalone verifier with a challenge store, a status registry path, and
/// one holder whose passport answers every registered challenge.
struct HolderSubmissions {
    directory: tempfile::TempDir,
    state: TrustServiceState,
    challenge_db: PathBuf,
    holder: Keypair,
    passport: AgentPassport,
    now: u64,
}

impl HolderSubmissions {
    fn new() -> Self {
        let directory = chio_test_support::private_tempdir().test_unwrap();
        let challenge_db = directory.path().join("verifier-challenges.sqlite3");
        let mut state = state_with_cluster(SELF_URL, &[], None, None, None);
        assert!(state.cluster.is_none());
        state.config.verifier_challenge_db_path = Some(challenge_db.clone());
        state.config.passport_statuses_file = Some(directory.path().join("passport-statuses"));
        let now = unix_timestamp_now().test_unwrap();
        let holder = Keypair::from_seed(&[61; 32]);
        let scorecard = chio_reputation::compute_local_scorecard(
            &holder.public_key().to_hex(),
            now,
            &chio_reputation::LocalReputationCorpus::default(),
            &chio_reputation::ReputationConfig::default(),
        );
        let credential = issue_reputation_credential(
            &Keypair::from_seed(&[62; 32]),
            scorecard,
            ChioCredentialEvidence {
                query: AttestationWindow {
                    since: None,
                    until: now,
                },
                receipt_count: 0,
                receipt_ids: Vec::new(),
                checkpoint_roots: Vec::new(),
                receipt_log_urls: Vec::new(),
                lineage_records: 0,
                uncheckpointed_receipts: 0,
                runtime_attestation: None,
            },
            now.saturating_sub(60),
            now.saturating_add(7_200),
        )
        .test_unwrap();
        let subject = credential.unsigned.credential_subject.id.clone();
        let passport = build_agent_passport(&subject, vec![credential]).test_unwrap();
        Self {
            directory,
            state,
            challenge_db,
            holder,
            passport,
            now,
        }
    }

    fn status_registry(
        &self,
    ) -> (
        PausedStatusRegistry,
        tokio::sync::mpsc::UnboundedReceiver<()>,
    ) {
        PausedStatusRegistry::serve(self.directory.path().join("passport-statuses"))
    }

    /// Registers a fresh single-use challenge and returns the holder's signed
    /// answer to it.
    fn submission(&self, challenge_id: &str) -> VerifyPassportChallengeRequest {
        let challenge = create_passport_presentation_challenge_with_reference(
            PassportPresentationChallengeArgs {
                verifier: VERIFIER.to_string(),
                challenge_id: Some(challenge_id.to_string()),
                nonce: format!("nonce-{challenge_id}"),
                issued_at: self.now,
                expires_at: self.now.saturating_add(600),
                options: PassportPresentationOptions::default(),
                policy_ref: None,
                policy: None,
            },
        )
        .test_unwrap();
        let store = SqlitePassportVerifierStore::open(&self.challenge_db).test_unwrap();
        register_presentation_challenge(&store, &challenge).test_unwrap();
        let presentation = respond_to_passport_presentation_challenge(
            &self.holder,
            &self.passport,
            &challenge,
            self.now,
        )
        .test_unwrap();
        VerifyPassportChallengeRequest {
            presentation,
            expected_challenge: None,
        }
    }
}

async fn verification_of(response: Response) -> PassportPresentationVerification {
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    serde_json::from_slice(&body).test_unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn public_challenge_verification_leaves_the_async_worker_free_while_its_status_read_is_paused(
) {
    let holders = HolderSubmissions::new();
    let (registry, mut opened) = holders.status_registry();
    let submission = holders.submission("public-holder-progress");
    let verification_finished = Arc::new(AtomicBool::new(false));
    let verification = tokio::spawn({
        let state = holders.state.clone();
        let verification_finished = Arc::clone(&verification_finished);
        async move {
            let response =
                handle_public_verify_passport_challenge(State(state), Json(submission)).await;
            verification_finished.store(true, Ordering::SeqCst);
            response
        }
    });
    // A second task on the same single worker. It can observe the paused
    // status read while the verification is still outstanding only if the
    // verification yields the worker instead of blocking it on the read.
    let (progress_tx, progress_rx) = tokio::sync::oneshot::channel();
    let observed = Arc::clone(&verification_finished);
    tokio::spawn(async move {
        let paused_in_verification = opened.recv().await.is_some();
        let _ = progress_tx.send(paused_in_verification && !observed.load(Ordering::SeqCst));
    });

    let progressed_while_outstanding = tokio::time::timeout(HANG_GUARD, progress_rx)
        .await
        .test_unwrap()
        .test_unwrap();
    assert!(
        progressed_while_outstanding,
        "a task on the verifying worker made no progress until the public challenge verification ended"
    );

    registry.release();
    let response = tokio::time::timeout(HANG_GUARD, verification)
        .await
        .test_unwrap()
        .test_unwrap();
    let verification = verification_of(response).await;
    assert!(verification.accepted);
    assert_eq!(
        verification.challenge_id.as_deref(),
        Some("public-holder-progress")
    );
    assert_eq!(verification.replay_state.as_deref(), Some("consumed"));
}

const AT_CAPACITY: &str = "public passport challenge verification is at capacity";

async fn assert_same_response(actual: Response, expected: Response) {
    assert_eq!(actual.status(), expected.status());
    assert_eq!(
        actual.headers().get(CONTENT_TYPE),
        expected.headers().get(CONTENT_TYPE)
    );
    let actual = to_bytes(actual.into_body(), usize::MAX).await.test_unwrap();
    let expected = to_bytes(expected.into_body(), usize::MAX)
        .await
        .test_unwrap();
    assert_eq!(actual, expected);
}

/// Starts a verification on a one-permit lane and returns once it is paused
/// inside its status read, holding that permit.
async fn held_verification(
    holders: &HolderSubmissions,
) -> (
    PausedStatusRegistry,
    Arc<tokio::sync::Semaphore>,
    tokio::task::JoinHandle<Response>,
) {
    let (registry, mut opened) = holders.status_registry();
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let submission = holders.submission("public-holder-held");
    let verification = tokio::spawn({
        let lane = Arc::clone(&lane);
        let state = holders.state.clone();
        async move { verify_public_passport_challenge_in_lane(&lane, state, submission).await }
    });
    tokio::time::timeout(HANG_GUARD, opened.recv())
        .await
        .test_unwrap()
        .test_unwrap();
    assert_eq!(lane.available_permits(), 0);
    (registry, lane, verification)
}

/// Polls one more verification on `lane` exactly once. One that would wait
/// for admission is not ready and fails the `test_unwrap`.
fn next_verification_polled_once(
    holders: &HolderSubmissions,
    lane: &Arc<tokio::sync::Semaphore>,
    challenge_id: &str,
) -> Response {
    verify_public_passport_challenge_in_lane(
        lane,
        holders.state.clone(),
        holders.submission(challenge_id),
    )
    .now_or_never()
    .test_unwrap()
}

fn challenge_status(holders: &HolderSubmissions, challenge_id: &str) -> Result<(), String> {
    let store = SqlitePassportVerifierStore::open(&holders.challenge_db).test_unwrap();
    fetch_active_presentation_challenge(&store, challenge_id, holders.now)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[tokio::test(flavor = "current_thread")]
async fn next_public_challenge_verification_is_refused_at_once_while_a_paused_one_holds_the_permit()
{
    let holders = HolderSubmissions::new();
    let (registry, lane, held) = held_verification(&holders).await;

    let refused = next_verification_polled_once(&holders, &lane, "public-holder-refused");
    assert_same_response(
        refused,
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await;
    assert_eq!(challenge_status(&holders, "public-holder-refused"), Ok(()));

    registry.release();
    let response = tokio::time::timeout(HANG_GUARD, held)
        .await
        .test_unwrap()
        .test_unwrap();
    let verification = verification_of(response).await;
    assert!(verification.accepted);
    assert_eq!(verification.replay_state.as_deref(), Some("consumed"));
    assert_eq!(lane.available_permits(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_public_challenge_verification_keeps_its_permit_until_the_verification_ends() {
    let holders = HolderSubmissions::new();
    let (registry, lane, held) = held_verification(&holders).await;

    held.abort();
    let cancelled = tokio::time::timeout(HANG_GUARD, held)
        .await
        .test_unwrap()
        .test_unwrap_err();
    assert!(cancelled.is_cancelled());
    assert_eq!(lane.available_permits(), 0);
    let refused = next_verification_polled_once(&holders, &lane, "public-holder-after-cancel");
    assert_same_response(
        refused,
        plain_http_error(StatusCode::SERVICE_UNAVAILABLE, AT_CAPACITY),
    )
    .await;

    registry.release();
    let returned = tokio::time::timeout(HANG_GUARD, Arc::clone(&lane).acquire_owned())
        .await
        .test_unwrap()
        .test_unwrap();
    drop(returned);
    assert_eq!(lane.available_permits(), 1);
    // The dropped request's verification still ran to its end.
    let consumed = challenge_status(&holders, "public-holder-held").test_unwrap_err();
    assert!(consumed.contains("has already been consumed"), "{consumed}");
}
