//! Actual authenticated recovery RPCs over a private temporary joint authority.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationKind, AdmissionOperationStore,
    AdmissionOperationV1, AdmissionParticipantRequirements, AdmissionRecoveryDeferralClear,
    AdmissionRecoveryDeferralV1, AdmissionRecoveryDeferralWrite, AdmissionRecoveryFailureKind,
    AdmissionRecoveryLease, AdmissionRecoveryPageQuery, AdmissionRecoveryPhase,
    AdmissionRecoveryStatusV1, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
    QualifiedAdmissionOperationStoreExt, SideEffectClass, StoreMutationFence,
};
use chio_security_types::clock::FixedClock;
use chio_store_sqlite::SqliteAdmissionOperationStore;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const AUTHORITY_TIME: u64 = 1_700_000_000_000;

struct Fixture {
    _directory: tempfile::TempDir,
    database: std::path::PathBuf,
    authority: Arc<SqliteAuthorityStore>,
    executor: tokio::runtime::Runtime,
    server: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    reply_fault: Arc<AtomicU8>,
    url: String,
    remote: crate::trust_control::service_runtime::remote_admission::RemoteAdmissionStores,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::with_clock(Arc::new(FixedClock::from_millis(AUTHORITY_TIME)))
    }

    fn with_clock(clock: Arc<dyn chio_security_types::clock::Clock>) -> TestResult<Self> {
        let directory = crate::durable_admission::private_tempdir()?;
        let database = directory.path().join("recovery-rpc.db");
        let locks = directory.path().join("locks");
        crate::create_private_directory(&locks)?;
        SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = Arc::new(SqliteAuthorityStore::open_serving_with_clock(
            &database, &locks, clock,
        )?);
        let mut state = metrics_state("recovery-rpc-secret");
        state.joint_authority_store = Some(authority.clone());
        let reply_fault = Arc::new(AtomicU8::new(0));
        let router = crate::trust_control::service_runtime::router::build_router(state).layer(
            axum::middleware::from_fn_with_state(reply_fault.clone(), fault_reply),
        );
        let executor = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (url, server) = executor.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}", listener.local_addr()?);
            let server = tokio::spawn(async move { axum::serve(listener, router).await });
            Ok::<_, std::io::Error>((url, server))
        })?;
        let remote =
            crate::trust_control::service_runtime::remote_admission::build_remote_admission_stores(
                &url,
                "recovery-rpc-secret",
                chio_core::Keypair::generate(),
            )?;
        assert_eq!(remote.fence, authority.mutation_fence());
        Ok(Self {
            _directory: directory,
            database,
            authority,
            executor,
            server: Some(server),
            reply_fault,
            url,
            remote,
        })
    }

    fn operations(&self) -> SqliteAdmissionOperationStore {
        self.authority.admission_operation_store()
    }

    fn stop_server(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
            self.executor.block_on(async {
                let _ = server.await;
            });
        }
    }

    fn fence(&self) -> StoreMutationFence {
        self.authority.mutation_fence()
    }

    fn operation(&self, request_id: &str) -> TestResult<AdmissionOperationV1> {
        let identifier = |field, value: &str| AdmissionIdentifier::try_new(field, value);
        let digest =
            |field, value: char| AdmissionDigest::try_new(field, value.to_string().repeat(64));
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::GovernedEconomicMutation,
            namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
                "coordinator_authority_id",
                "rpc-recovery-authority",
            )?)?,
            request_id: identifier("request_id", request_id)?,
            capability_id: identifier("capability_id", request_id)?,
            authorization_capability_hash: digest("authorization_capability_hash", 'a')?,
            request_binding: AdmissionRequestBindingV1::new(
                digest("immutable_request_hash", 'b')?,
                AdmissionParticipantRequirements::NONE,
            )?,
            policy_hash: digest("policy_hash", 'c')?,
            effect_class: SideEffectClass::SideEffecting,
        })?;
        let operation = AdmissionOperationV1::prepare(binding, self.fence().owner_epoch)?;
        self.operations()
            .begin(&operation, &self.fence(), AUTHORITY_TIME)?;
        Ok(operation)
    }

    fn lease(&self, operation: &AdmissionOperationV1) -> TestResult<AdmissionRecoveryLease> {
        Ok(self.operations().claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &AdmissionIdentifier::try_new("claimant_id", "rpc-recovery-worker")?,
            AUTHORITY_TIME,
            AUTHORITY_TIME + 120_000,
            &self.fence(),
        )?)
    }

    fn deferral(
        &self,
        operation: &AdmissionOperationV1,
        now: u64,
    ) -> TestResult<AdmissionRecoveryDeferralV1> {
        Ok(AdmissionRecoveryDeferralV1::after_failure(
            operation,
            None,
            AdmissionRecoveryPhase::Inspection,
            AdmissionRecoveryFailureKind::ParticipantUnavailable,
            AdmissionDigest::try_new("diagnostic_digest", "d".repeat(64))?,
            now,
        )?)
    }

    fn local_deferral(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
    ) -> TestResult<AdmissionRecoveryStatusV1> {
        Ok(self
            .operations()
            .defer_recovery(AdmissionRecoveryDeferralWrite {
                operation,
                lease,
                expected: None,
                deferral: &self.deferral(operation, AUTHORITY_TIME)?,
                fence: &self.fence(),
                trusted_now_unix_ms: AUTHORITY_TIME,
            })?)
    }

    fn claim_commits(&self) -> TestResult<i64> {
        let connection = rusqlite::Connection::open_with_flags(
            &self.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM admission_operation_commits WHERE mutation_kind='recovery_claim'",
            [],
            |row| row.get(0),
        )?)
    }

    fn head(&self) -> TestResult<i64> {
        let connection = rusqlite::Connection::open_with_flags(
            &self.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(connection.query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)
    }

    fn wire_call(
        &self,
        request: &AdmissionAuthorityRequest,
    ) -> TestResult<AdmissionAuthorityResponse> {
        let response = ureq::post(&format!("{}{INTERNAL_ADMISSION_AUTHORITY_PATH}", self.url))
            .set("authorization", "Bearer recovery-rpc-secret")
            .send_json(serde_json::to_value(request)?)?;
        Ok(crate::json_input::read(response.into_reader(), 64 * 1024)?)
    }
}

struct MutableClock {
    now: AtomicU64,
    failed: AtomicBool,
}

impl MutableClock {
    fn new() -> Self {
        Self {
            now: AtomicU64::new(AUTHORITY_TIME),
            failed: AtomicBool::new(false),
        }
    }
}

impl chio_security_types::clock::Clock for MutableClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::{ClockError, ClockReading, MonotonicInstant, UnixMillis};
        if self.failed.load(Ordering::SeqCst) {
            return Err(ClockError::Unavailable);
        }
        Ok(ClockReading::new(
            UnixMillis::new(self.now.load(Ordering::SeqCst)),
            MonotonicInstant::from_nanos(0),
        ))
    }
}

async fn fault_reply(
    State(mode): State<Arc<AtomicU8>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if mode.load(Ordering::SeqCst) == 1 {
        return (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            "{\"PRIVATE_RECOVERY_PARSE_CANARY\":",
        )
            .into_response();
    }
    if mode.load(Ordering::SeqCst) == 2 {
        return Json(AdmissionAuthorityResponse::failure(
            AdmissionAuthorityErrorCode::Fenced,
            "PRIVATE_REMOTE_ERROR_CANARY outcome unknown invariant timeout",
        ))
        .into_response();
    }
    if mode.load(Ordering::SeqCst) == 3 {
        return Json(
            AdmissionAuthorityResponse::success(&serde_json::json!({
                "operations": [], "scanned_candidates": 257, "next_cursor": null,
            }))
            .test_unwrap(),
        )
        .into_response();
    }
    next.run(request).await
}

fn has_source<T: Error + 'static>(error: &(dyn Error + 'static)) -> bool {
    let mut cause = Some(error);
    for _ in 0..16 {
        match cause {
            Some(error) if error.is::<T>() => return true,
            Some(error) => cause = error.source(),
            None => break,
        }
    }
    false
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop_server();
    }
}

#[test]
fn remote_recovery_rpc_page_reaches_actual_authority() -> TestResult {
    let fixture = Fixture::new()?;
    let operation = fixture.operation("rpc-page")?;
    let page = fixture
        .remote
        .operations
        .recovery_page(AdmissionRecoveryPageQuery {
            not_after_unix_ms: AUTHORITY_TIME + 300_000,
            candidate_limit: 2,
            after_operation_id: None,
            fence: &fixture.fence(),
        });
    let page = match page {
        Ok(page) => page,
        Err(error) => panic!("bounded recovery page RPC remains unsupported: {error}"),
    };
    assert_eq!(page.operations, vec![operation]);
    assert_eq!(page.scanned_candidates, 1);
    assert!(page.next_cursor.is_none());
    Ok(())
}

#[test]
fn remote_recovery_rpc_status_preserves_authoritative_absence() -> TestResult {
    let fixture = Fixture::new()?;
    let operation = fixture.operation("rpc-status")?;
    let status = fixture.remote.operations.load_recovery_status(
        operation.binding().operation_id(),
        &fixture.fence(),
        AUTHORITY_TIME + 300_000,
    );
    let status = match status {
        Ok(status) => status,
        Err(error) => panic!("recovery status RPC remains unsupported: {error}"),
    };
    assert!(status.is_none());
    Ok(())
}

#[test]
fn remote_recovery_rpc_defer_uses_server_clock_and_original_claim() -> TestResult {
    let fixture = Fixture::new()?;
    let operation = fixture.operation("rpc-defer")?;
    let lease = fixture.lease(&operation)?;
    let original_claim = lease.untrusted_claim().clone();
    let claim_commits = fixture.claim_commits()?;
    let hostile_time = AUTHORITY_TIME + 300_000;
    let deferral = fixture.deferral(&operation, hostile_time)?;
    let result = fixture
        .remote
        .operations
        .defer_recovery(AdmissionRecoveryDeferralWrite {
            operation: &operation,
            lease: &lease,
            expected: None,
            deferral: &deferral,
            fence: &fixture.fence(),
            trusted_now_unix_ms: hostile_time,
        });
    let returned = match result {
        Ok(status) => status,
        Err(error) => panic!("recovery deferral RPC remains unsupported: {error}"),
    };
    let status = fixture
        .operations()
        .load_recovery_status(
            operation.binding().operation_id(),
            &fixture.fence(),
            AUTHORITY_TIME,
        )?
        .ok_or("missing durable deferral")?;
    assert_eq!(returned, status);
    assert!(status.quarantined);
    assert_eq!(status.deferral.last_failure_unix_ms, AUTHORITY_TIME);
    assert_eq!(
        status.deferral.retry_not_before_unix_ms,
        AUTHORITY_TIME + 60_000
    );
    assert_eq!(status.deferral.attempt_count, 1);
    assert_eq!(fixture.claim_commits()?, claim_commits);
    fixture.operations().revalidate_recovery_claim(
        &operation,
        &original_claim,
        AUTHORITY_TIME,
        &fixture.fence(),
    )?;
    assert_eq!(
        fixture
            .operations()
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}

#[test]
fn remote_recovery_rpc_clear_retains_attempt_history() -> TestResult {
    let fixture = Fixture::new()?;
    let operation = fixture.operation("rpc-clear")?;
    let lease = fixture.lease(&operation)?;
    let original_claim = lease.untrusted_claim().clone();
    let status = fixture.local_deferral(&operation, &lease)?;
    let claim_commits = fixture.claim_commits()?;
    let result =
        fixture
            .remote
            .operations
            .clear_recovery_deferral(AdmissionRecoveryDeferralClear {
                operation: &operation,
                lease: Some(&lease),
                expected: &status,
                fence: &fixture.fence(),
                trusted_now_unix_ms: AUTHORITY_TIME + 300_000,
            });
    if let Err(error) = result {
        panic!("recovery deferral clear RPC remains unsupported: {error}");
    }
    let retained = fixture
        .operations()
        .load_recovery_status(
            operation.binding().operation_id(),
            &fixture.fence(),
            AUTHORITY_TIME,
        )?
        .ok_or("clearing removed anchored attempt history")?;
    assert!(!retained.quarantined);
    assert_eq!(retained.deferral, status.deferral);
    assert_eq!(fixture.claim_commits()?, claim_commits);
    fixture.operations().revalidate_recovery_claim(
        &operation,
        &original_claim,
        AUTHORITY_TIME,
        &fixture.fence(),
    )?;
    assert_eq!(
        fixture
            .operations()
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}

#[test]
fn remote_recovery_rpc_transport_retains_actual_native_source() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.stop_server();
    let error = fixture
        .remote
        .operations
        .recovery_page(AdmissionRecoveryPageQuery {
            not_after_unix_ms: AUTHORITY_TIME,
            candidate_limit: 1,
            after_operation_id: None,
            fence: &fixture.fence(),
        })
        .err()
        .ok_or("stopped authority listener returned a recovery page")?;
    assert!(
        has_source::<ureq::Transport>(&error),
        "recovery RPC discarded the actual native transport cause"
    );
    assert_eq!(
        error.kind(),
        chio_kernel::admission_operation::RemoteRecoveryFailureKind::Unavailable
    );
    Ok(())
}

#[test]
fn remote_recovery_rpc_malformed_reply_retains_actual_native_source() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.reply_fault.store(1, Ordering::SeqCst);
    let error = fixture
        .remote
        .operations
        .recovery_page(AdmissionRecoveryPageQuery {
            not_after_unix_ms: AUTHORITY_TIME,
            candidate_limit: 1,
            after_operation_id: None,
            fence: &fixture.fence(),
        })
        .err()
        .ok_or("malformed authority response returned a recovery page")?;
    assert!(
        has_source::<crate::CliError>(&error),
        "recovery RPC discarded the native bounded JSON reader cause"
    );
    assert_eq!(
        error.kind(),
        chio_kernel::admission_operation::RemoteRecoveryFailureKind::Invariant
    );
    assert!(!format!("{error:?} {error}").contains("PRIVATE_RECOVERY_PARSE_CANARY"));
    Ok(())
}

#[test]
fn remote_recovery_guard_page_preserves_progress_past_a_deferred_candidate() -> TestResult {
    let clock = Arc::new(MutableClock::new());
    let fixture = Fixture::with_clock(clock.clone())?;
    let mut operations = [
        fixture.operation("rpc-page-first")?,
        fixture.operation("rpc-page-second")?,
    ];
    operations.sort_by(|left, right| {
        left.binding()
            .operation_id()
            .cmp(right.binding().operation_id())
    });
    let first = &operations[0];
    let lease = fixture.operations().claim_recovery(
        first.binding().operation_id(),
        first.version(),
        &AdmissionIdentifier::try_new("claimant_id", "rpc-cursor-worker")?,
        AUTHORITY_TIME,
        AUTHORITY_TIME + 1_000,
        &fixture.fence(),
    )?;
    fixture.local_deferral(first, &lease)?;
    clock.now.store(AUTHORITY_TIME + 1_001, Ordering::SeqCst);
    let page = fixture
        .remote
        .operations
        .recovery_page(AdmissionRecoveryPageQuery {
            not_after_unix_ms: AUTHORITY_TIME + 300_000,
            candidate_limit: 1,
            after_operation_id: None,
            fence: &fixture.fence(),
        })?;
    assert!(page.operations.is_empty());
    assert_eq!(page.scanned_candidates, 1);
    assert_eq!(
        page.next_cursor.as_ref(),
        Some(first.binding().operation_id())
    );
    let after = page
        .next_cursor
        .ok_or("empty deferred page lost its progress cursor")?;
    let next = fixture
        .remote
        .operations
        .recovery_page(AdmissionRecoveryPageQuery {
            not_after_unix_ms: 1,
            candidate_limit: 1,
            after_operation_id: Some(&after),
            fence: &fixture.fence(),
        })?;
    assert_eq!(next.operations, vec![operations[1].clone()]);
    assert_eq!(next.scanned_candidates, 1);
    assert_eq!(
        next.next_cursor.as_ref(),
        Some(operations[1].binding().operation_id())
    );
    Ok(())
}

#[test]
fn remote_recovery_guard_caller_time_cannot_expire_a_live_claim() -> TestResult {
    let fixture = Fixture::new()?;
    let operation = fixture.operation("rpc-live-claim")?;
    let lease = fixture.lease(&operation)?;
    let page = fixture
        .remote
        .operations
        .recovery_page(AdmissionRecoveryPageQuery {
            not_after_unix_ms: AUTHORITY_TIME + 300_000,
            candidate_limit: 1,
            after_operation_id: None,
            fence: &fixture.fence(),
        })?;
    assert!(page.operations.is_empty());
    assert_eq!(page.scanned_candidates, 0);
    assert!(page.next_cursor.is_none());
    fixture.operations().revalidate_recovery_claim(
        &operation,
        lease.untrusted_claim(),
        AUTHORITY_TIME,
        &fixture.fence(),
    )?;
    Ok(())
}

#[test]
fn remote_recovery_guard_marker_cas_and_monotone_attempts_survive_clear() -> TestResult {
    let fixture = Fixture::new()?;
    let operation = fixture.operation("rpc-marker-cas")?;
    let lease = fixture.lease(&operation)?;
    let first = fixture.local_deferral(&operation, &lease)?;
    let caller_deferral = fixture.deferral(&operation, AUTHORITY_TIME + 300_000)?;
    let second = fixture
        .remote
        .operations
        .defer_recovery(AdmissionRecoveryDeferralWrite {
            operation: &operation,
            lease: &lease,
            expected: Some(&first),
            deferral: &caller_deferral,
            fence: &fixture.fence(),
            trusted_now_unix_ms: AUTHORITY_TIME + 300_000,
        })?;
    assert_eq!(second.deferral.attempt_count, 2);
    assert_eq!(second.deferral.last_failure_unix_ms, AUTHORITY_TIME);
    assert_eq!(
        second.deferral.retry_not_before_unix_ms,
        AUTHORITY_TIME + 120_000
    );
    let before = fixture.head()?;
    let stale = fixture
        .remote
        .operations
        .clear_recovery_deferral(AdmissionRecoveryDeferralClear {
            operation: &operation,
            lease: Some(&lease),
            expected: &first,
            fence: &fixture.fence(),
            trusted_now_unix_ms: AUTHORITY_TIME,
        })
        .err()
        .ok_or("stale marker cleared current deferral")?;
    assert_eq!(
        stale.kind(),
        chio_kernel::admission_operation::RemoteRecoveryFailureKind::Invariant
    );
    assert_eq!(fixture.head()?, before);
    fixture
        .remote
        .operations
        .clear_recovery_deferral(AdmissionRecoveryDeferralClear {
            operation: &operation,
            lease: Some(&lease),
            expected: &second,
            fence: &fixture.fence(),
            trusted_now_unix_ms: AUTHORITY_TIME + 300_000,
        })?;
    let retained = fixture
        .remote
        .operations
        .load_recovery_status(operation.binding().operation_id(), &fixture.fence(), 1)?
        .ok_or("attempt tombstone disappeared")?;
    assert!(!retained.quarantined);
    assert_eq!(retained.deferral, second.deferral);
    let third = fixture
        .remote
        .operations
        .defer_recovery(AdmissionRecoveryDeferralWrite {
            operation: &operation,
            lease: &lease,
            expected: Some(&retained),
            deferral: &caller_deferral,
            fence: &fixture.fence(),
            trusted_now_unix_ms: 1,
        })?;
    assert_eq!(third.deferral.attempt_count, 3);
    assert_eq!(
        third.deferral.retry_not_before_unix_ms,
        AUTHORITY_TIME + 240_000
    );
    assert_eq!(fixture.claim_commits()?, 1);
    Ok(())
}

#[test]
fn remote_recovery_guard_requires_service_auth_current_fence_and_original_claim() -> TestResult {
    let fixture = Fixture::new()?;
    let operation = fixture.operation("rpc-identity")?;
    let lease = fixture.lease(&operation)?;
    let before = fixture.head()?;
    for action in [
        AdmissionAuthorityAction::RecoveryPage,
        AdmissionAuthorityAction::LoadRecoveryStatus,
        AdmissionAuthorityAction::DeferRecovery,
        AdmissionAuthorityAction::ClearRecoveryDeferral,
    ] {
        let request = AdmissionAuthorityRequest::new(
            Some(fixture.fence()),
            action,
            &serde_json::Value::Null,
        )?;
        let error = ureq::post(&format!(
            "{}{INTERNAL_ADMISSION_AUTHORITY_PATH}",
            fixture.url
        ))
        .set("authorization", "Bearer wrong-service-token")
        .send_json(serde_json::to_value(&request)?)
        .err()
        .ok_or("recovery RPC accepted an invalid service token")?;
        assert!(matches!(error, ureq::Error::Status(401, _)));
        let mut stale = request;
        stale
            .expected_fence
            .as_mut()
            .ok_or("missing request fence")?
            .owner_epoch += 1;
        let response = fixture.wire_call(&stale)?;
        assert_eq!(
            response
                .error
                .ok_or("stale owner had an authoritative outcome")?
                .code,
            AdmissionAuthorityErrorCode::Fenced
        );
    }
    let mut claim = RecoveryClaimWire::from_claim(lease.untrusted_claim());
    claim.expires_at_unix_ms += 1;
    let request = AdmissionAuthorityRequest::new(
        Some(fixture.fence()),
        AdmissionAuthorityAction::DeferRecovery,
        &RecoveryDeferralRequest {
            operation: operation.to_persisted(),
            recovery_claim: claim,
            expected: None,
            phase: AdmissionRecoveryPhase::Inspection,
            failure_kind: AdmissionRecoveryFailureKind::ParticipantUnavailable,
            diagnostic_digest: AdmissionDigest::try_new("diagnostic_digest", "d".repeat(64))?,
            fence: fixture.fence(),
        },
    )?;
    let response = fixture.wire_call(&request)?;
    assert!(response.result.is_none());
    assert_eq!(
        response
            .error
            .ok_or("changed original claim was accepted")?
            .code,
        AdmissionAuthorityErrorCode::Fenced
    );
    assert_eq!(fixture.head()?, before);
    assert_eq!(fixture.claim_commits()?, 1);
    Ok(())
}

#[test]
fn remote_recovery_guard_nonterminal_clear_requires_original_lease() -> TestResult {
    let fixture = Fixture::new()?;
    let operation = fixture.operation("rpc-clear-no-lease")?;
    let lease = fixture.lease(&operation)?;
    let expected = fixture.local_deferral(&operation, &lease)?;
    let before = fixture.head()?;
    let error = fixture
        .remote
        .operations
        .clear_recovery_deferral(AdmissionRecoveryDeferralClear {
            operation: &operation,
            lease: None,
            expected: &expected,
            fence: &fixture.fence(),
            trusted_now_unix_ms: AUTHORITY_TIME,
        })
        .err()
        .ok_or("nonterminal operation cleared without its original lease")?;
    assert_eq!(
        error.kind(),
        chio_kernel::admission_operation::RemoteRecoveryFailureKind::Invariant
    );
    assert_eq!(fixture.head()?, before);
    assert_eq!(
        fixture.operations().load_recovery_status(
            operation.binding().operation_id(),
            &fixture.fence(),
            AUTHORITY_TIME
        )?,
        Some(expected)
    );
    Ok(())
}

#[test]
fn remote_recovery_guard_clock_failure_remains_global_and_preserves_wire_source() -> TestResult {
    let clock = Arc::new(MutableClock::new());
    let fixture = Fixture::with_clock(clock.clone())?;
    let operation = fixture.operation("rpc-clock-error")?;
    let before = fixture.head()?;
    clock.failed.store(true, Ordering::SeqCst);
    let local = fixture
        .operations()
        .observed_authority_time()
        .err()
        .ok_or("failed clock returned local authority time")?;
    assert_eq!(
        local,
        chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
            chio_security_types::clock::ClockError::Unavailable
                .code()
                .to_owned()
        )
    );
    let error = fixture
        .remote
        .operations
        .load_recovery_status(
            operation.binding().operation_id(),
            &fixture.fence(),
            AUTHORITY_TIME + 300_000,
        )
        .err()
        .ok_or("unavailable backend clock became authoritative absence")?;
    assert_eq!(
        error.kind(),
        chio_kernel::admission_operation::RemoteRecoveryFailureKind::Invariant
    );
    assert!(error.source().is_some());
    assert_eq!(fixture.head()?, before);
    Ok(())
}

#[test]
fn remote_recovery_guard_validates_page_bounds_and_ignores_wire_error_prose() -> TestResult {
    let fixture = Fixture::new()?;
    for limit in [0, 257] {
        let error = fixture
            .remote
            .operations
            .recovery_page(AdmissionRecoveryPageQuery {
                not_after_unix_ms: AUTHORITY_TIME,
                candidate_limit: limit,
                after_operation_id: None,
                fence: &fixture.fence(),
            })
            .err()
            .ok_or("invalid candidate count was accepted")?;
        assert_eq!(
            error.kind(),
            chio_kernel::admission_operation::RemoteRecoveryFailureKind::Invariant
        );
    }
    for (mode, kind) in [
        (
            2,
            chio_kernel::admission_operation::RemoteRecoveryFailureKind::Fenced,
        ),
        (
            3,
            chio_kernel::admission_operation::RemoteRecoveryFailureKind::Invariant,
        ),
    ] {
        fixture.reply_fault.store(mode, Ordering::SeqCst);
        let error = fixture
            .remote
            .operations
            .recovery_page(AdmissionRecoveryPageQuery {
                not_after_unix_ms: AUTHORITY_TIME,
                candidate_limit: 1,
                after_operation_id: None,
                fence: &fixture.fence(),
            })
            .err()
            .ok_or("forged authority page or refusal became success")?;
        assert_eq!(error.kind(), kind);
        assert!(!format!("{error:?} {error}").contains("PRIVATE_REMOTE_ERROR_CANARY"));
    }
    Ok(())
}
