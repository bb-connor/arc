    use chio_test_support::prelude::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Barrier, Mutex};
    use std::thread;

    use chio_core_types::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_core_types::{Error as CoreError, Signature, SigningAlgorithm};

    use crate::budget::{
        CombinedCaptureCommit, ExecutionAuthorityCapabilities, ExecutionAuthorityProfile,
        QueryExecutionHoldRequest,
    };
    use crate::capability::issue_capability;
    use crate::generic_https::{
        DestinationResolver, NetworkPolicy, PinnedHttpsRequest, PinnedHttpsTransport,
        RawHttpsResponse,
    };
    use crate::proof::{body_digest, issue_request_proof};
    use crate::protocol::{
        AttemptConsumption, BrokerCapabilityBody, BrokerDestination, BrokerRequest, CallerOptions,
        CredentialRef, HeaderField, ProofBinding, ProofMode, RedirectPolicy, RequestConstraints,
        BROKER_CAPABILITY_SCHEMA, BROKER_EXECUTE_SCHEMA,
    };
    use crate::provider::CredentialPlacement;
    use crate::receipt::{SignedBrokerFailureReceipt, SignedBrokerReceipt};
    use crate::revocation::{BrokerRevocationSnapshot, LiveParentCapability};
    use crate::sqlite::SqliteAttemptStore;

    use super::*;

    struct PublicResolver {
        calls: Arc<AtomicU64>,
    }

    impl DestinationResolver for PublicResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        }
    }

    struct ObservingTransport {
        observed_authorizations: Arc<Mutex<Vec<Vec<u8>>>>,
        fail: bool,
        redirect: bool,
    }

    impl PinnedHttpsTransport for ObservingTransport {
        fn dispatch(&self, request: PinnedHttpsRequest) -> Result<RawHttpsResponse> {
            assert!(!request.redirects_allowed());
            let values = request
                .secret_headers()
                .map(|(_name, value)| value.to_vec())
                .collect::<Vec<_>>();
            self.observed_authorizations
                .lock()
                .test_expect("observed lock")
                .extend(values);
            if self.fail {
                return Err(BrokerError::Upstream("injected timeout".to_string()));
            }
            let status = if self.redirect { 302 } else { 200 };
            let response = b"sanitized-upstream-response".to_vec();
            let (headers, response_head_bytes) = if self.redirect {
                (Vec::new(), b"HTTP/1.1 302 Found\r\n\r\n".len())
            } else {
                let value = response.len().to_string();
                let header = HeaderField::normalized("content-length", value.as_bytes())?;
                let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {value}\r\n\r\n");
                (vec![header], head.len())
            };
            Ok(RawHttpsResponse {
                status,
                headers,
                decoded_body_chunks: vec![response],
                response_head_bytes,
                connected_address: request.pinned_address(),
                tls_server_name: request.original_hostname().to_string(),
                redirected: false,
            })
        }
    }

    #[derive(Default)]
    struct AuthorityState {
        holds: HashMap<String, ExecutionHoldState>,
        quotas: HashMap<String, u32>,
        hold_quotas: HashMap<String, Vec<ExecutionQuota>>,
    }

    struct AtomicAuthority {
        state: Mutex<AuthorityState>,
        deny_capture: bool,
        deny_migration_after_capture:
            Mutex<Option<Arc<crate::migration::TestBrokerMigrationEnforcer>>>,
    }

    impl AtomicAuthority {
        fn new(deny_capture: bool) -> Self {
            Self {
                state: Mutex::new(AuthorityState::default()),
                deny_capture,
                deny_migration_after_capture: Mutex::new(None),
            }
        }

        fn captured_count(&self) -> usize {
            self.state
                .lock()
                .test_expect("authority lock")
                .holds
                .values()
                .filter(|state| matches!(state, ExecutionHoldState::Captured(_)))
                .count()
        }

        fn set_hold_state(&self, hold_id: &str, state: ExecutionHoldState) {
            self.state
                .lock()
                .test_expect("authority lock")
                .holds
                .insert(hold_id.to_string(), state);
        }

        fn deny_migration_after_next_capture(
            &self,
            enforcer: Arc<crate::migration::TestBrokerMigrationEnforcer>,
        ) {
            *self
                .deny_migration_after_capture
                .lock()
                .test_expect("migration capture hook lock") = Some(enforcer);
        }
    }

    impl BrokerExecutionBudget for AtomicAuthority {
        fn capabilities(&self) -> ExecutionAuthorityCapabilities {
            ExecutionAuthorityCapabilities {
                profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                atomic_multi_key_holds: true,
                combined_capture_and_revocation: true,
                query_by_id: true,
                shared_revocation_write_domain: true,
            }
        }

        fn query_execution_hold(
            &self,
            request: &QueryExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            Ok(self
                .state
                .lock()
                .test_expect("authority lock")
                .holds
                .get(&request.hold_id)
                .cloned()
                .unwrap_or(ExecutionHoldState::Unknown))
        }

        fn authorize_execution_hold(
            &self,
            request: &AuthorizeExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            request.validate()?;
            let mut state = self.state.lock().test_expect("authority lock");
            if let Some(existing) = state.holds.get(&request.hold_id) {
                return Ok(existing.clone());
            }
            let denied = request.quotas.iter().any(|quota| {
                state.quotas.get(&quota.key_id).copied().unwrap_or(0) >= quota.maximum_executions
            });
            if denied {
                state
                    .holds
                    .insert(request.hold_id.clone(), ExecutionHoldState::Denied);
                return Ok(ExecutionHoldState::Denied);
            }
            for quota in &request.quotas {
                let count = state.quotas.entry(quota.key_id.clone()).or_insert(0);
                *count = count.checked_add(1).ok_or_else(|| {
                    BrokerError::Invariant("test authority quota overflow".to_string())
                })?;
            }
            state
                .hold_quotas
                .insert(request.hold_id.clone(), request.quotas.clone());
            state
                .holds
                .insert(request.hold_id.clone(), ExecutionHoldState::Held);
            Ok(ExecutionHoldState::Held)
        }

        fn reverse_execution_hold(
            &self,
            request: &ReverseExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            if !request.proof_dispatch_did_not_begin {
                return Err(BrokerError::AuthorizationDenied(
                    "test reversal lacks dispatch proof".to_string(),
                ));
            }
            let mut state = self.state.lock().test_expect("authority lock");
            match state.holds.get(&request.hold_id) {
                Some(ExecutionHoldState::Reversed) => return Ok(ExecutionHoldState::Reversed),
                Some(ExecutionHoldState::Held) => {}
                _ => {
                    return Err(BrokerError::Conflict(
                        "test reversal found an incompatible hold".to_string(),
                    ))
                }
            }
            let quotas = state.hold_quotas.remove(&request.hold_id).ok_or_else(|| {
                BrokerError::Invariant("test authority lost hold quotas".to_string())
            })?;
            for quota in quotas {
                let count = state.quotas.get_mut(&quota.key_id).ok_or_else(|| {
                    BrokerError::Invariant("test authority lost quota".to_string())
                })?;
                *count = count.checked_sub(1).ok_or_else(|| {
                    BrokerError::Invariant("test authority quota underflow".to_string())
                })?;
            }
            state
                .holds
                .insert(request.hold_id.clone(), ExecutionHoldState::Reversed);
            Ok(ExecutionHoldState::Reversed)
        }

        fn capture_execution_hold(
            &self,
            request: &CaptureExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            request.validate()?;
            let mut state = self.state.lock().test_expect("authority lock");
            if let Some(ExecutionHoldState::Captured(commit)) = state.holds.get(&request.hold_id) {
                return Ok(ExecutionHoldState::Captured(commit.clone()));
            }
            if !matches!(
                state.holds.get(&request.hold_id),
                Some(ExecutionHoldState::Held)
            ) {
                return Err(BrokerError::Conflict(
                    "test capture found a non-held reservation".to_string(),
                ));
            }
            if self.deny_capture {
                state
                    .holds
                    .insert(request.hold_id.clone(), ExecutionHoldState::Denied);
                return Ok(ExecutionHoldState::Denied);
            }
            let index = u64::try_from(state.holds.len())
                .test_expect("hold count")
                .checked_add(1)
                .test_expect("index");
            let commit = CombinedCaptureCommit {
                checked_revocation_set_digest: request.revocation_set_digest.clone(),
                budget_commit_index: index,
                revocation_commit_index: index,
                authority_commit_index: index,
                leader_epoch: 1,
            };
            state.holds.insert(
                request.hold_id.clone(),
                ExecutionHoldState::Captured(commit.clone()),
            );
            drop(state);
            if let Some(enforcer) = self
                .deny_migration_after_capture
                .lock()
                .test_expect("migration capture hook lock")
                .take()
            {
                enforcer.set_quota_enforcement_enforced(false);
            }
            Ok(ExecutionHoldState::Captured(commit))
        }
    }

    struct LiveAuthority {
        calls: Arc<AtomicU64>,
        unavailable: Arc<AtomicBool>,
        broker_signer: Arc<dyn SigningBackend>,
        authority_signer: Arc<dyn SigningBackend>,
    }

    impl CapabilityLiveness for LiveAuthority {
        fn verify_live_parent(
            &self,
            request: &CapabilityLivenessRequest,
        ) -> Result<LiveParentCapability> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(BrokerError::AuthorityUnavailable(
                    "injected live-parent outage".to_string(),
                ));
            }
            Ok(LiveParentCapability {
                capability_id: request.parent_capability_id.clone(),
                subject: request.expected_subject.clone(),
                audience: request.expected_audience.clone(),
                delegation_ancestor_ids: vec!["delegation-ancestor".to_string()],
                expires_at_unix_seconds: 1_000,
                verified_at_unix_seconds: request.now_unix_seconds,
                authority_snapshot_digest: "a".repeat(64),
            })
        }

        fn verify_live_parent_with_audit_evidence(
            &self,
            request: &CapabilityLivenessRequest,
        ) -> Result<crate::authority_ipc::VerifiedAuthorityExchange> {
            let parent = self.verify_live_parent(request)?;
            crate::authority_ipc::sign_test_authority_exchange(
                crate::authority_ipc::AuthorityOperation::VerifyLiveParent(request.clone()),
                crate::authority_ipc::AuthorityResult::LiveParent(parent),
                request.now_unix_seconds,
                self.broker_signer.as_ref(),
                self.authority_signer.as_ref(),
                2,
            )
        }
    }

    struct LiveRevocations {
        calls: Arc<AtomicU64>,
        unavailable: Arc<AtomicBool>,
        broker_signer: Arc<dyn SigningBackend>,
        authority_signer: Arc<dyn SigningBackend>,
    }

    impl BrokerRevocations for LiveRevocations {
        fn check_broker_revocation(
            &self,
            request: &BrokerRevocationRequest,
        ) -> Result<BrokerRevocationSnapshot> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(BrokerError::AuthorityUnavailable(
                    "injected revocation outage".to_string(),
                ));
            }
            Ok(BrokerRevocationSnapshot {
                revoked: false,
                observed_at_unix_seconds: request.now_unix_seconds,
                commit_index: 1,
                authority_domain: "combined-authority".to_string(),
            })
        }

        fn check_broker_revocation_with_audit_evidence(
            &self,
            request: &BrokerRevocationRequest,
        ) -> Result<crate::authority_ipc::VerifiedAuthorityExchange> {
            let snapshot = self.check_broker_revocation(request)?;
            crate::authority_ipc::sign_test_authority_exchange(
                crate::authority_ipc::AuthorityOperation::CheckBrokerRevocation(
                    request.clone(),
                ),
                crate::authority_ipc::AuthorityResult::Revocation(snapshot),
                request.now_unix_seconds,
                self.broker_signer.as_ref(),
                self.authority_signer.as_ref(),
                2,
            )
        }
    }

    struct InspectingReceiptSink {
        canary: Vec<u8>,
        receipts: Arc<Mutex<Vec<Vec<u8>>>>,
        failures: Mutex<BTreeMap<String, SignedBrokerFailureReceipt>>,
        completed: Mutex<BTreeMap<String, BrokerExecuteResponse>>,
        failure_persist_entered: Option<Arc<Barrier>>,
        failure_persist_release: Option<Arc<Barrier>>,
        fail_completed: bool,
    }

    impl BrokerReceiptSink for InspectingReceiptSink {
        fn persist(&self, receipt: &SignedBrokerReceipt) -> Result<String> {
            let encoded = canonical_json_bytes(receipt)
                .map_err(|error| BrokerError::Storage(format!("test receipt: {error}")))?;
            if encoded
                .windows(self.canary.len())
                .any(|window| window == self.canary.as_slice())
            {
                return Err(BrokerError::Invariant(
                    "credential crossed into a receipt".to_string(),
                ));
            }
            self.receipts
                .lock()
                .test_expect("receipt lock")
                .push(encoded);
            Ok(format!(
                "broker-receipt-sha256-{}",
                receipt_digest(receipt)?
            ))
        }

        fn persist_failure(&self, receipt: &SignedBrokerFailureReceipt) -> Result<String> {
            let encoded = canonical_json_bytes(receipt)
                .map_err(|error| BrokerError::Storage(format!("test failure receipt: {error}")))?;
            if encoded
                .windows(self.canary.len())
                .any(|window| window == self.canary.as_slice())
            {
                return Err(BrokerError::Invariant(
                    "credential crossed into a failure receipt".to_string(),
                ));
            }
            if let Some(entered) = &self.failure_persist_entered {
                entered.wait();
            }
            if let Some(release) = &self.failure_persist_release {
                release.wait();
            }
            let mut failures = self.failures.lock().test_expect("failure lock");
            if let Some(existing) = failures.get(&receipt.body.receipt_id) {
                if existing != receipt {
                    return Err(BrokerError::Conflict(
                        "test failure receipt ID has different content".to_string(),
                    ));
                }
            } else {
                failures.insert(receipt.body.receipt_id.clone(), receipt.clone());
                self.receipts
                    .lock()
                    .test_expect("receipt lock")
                    .push(encoded);
            }
            Ok(format!(
                "broker-failure-receipt-sha256-{}",
                crate::receipt::failure_receipt_digest(receipt)?
            ))
        }

        fn load_failure(&self, receipt_id: &str) -> Result<Option<SignedBrokerFailureReceipt>> {
            Ok(self
                .failures
                .lock()
                .test_expect("failure lock")
                .get(receipt_id)
                .cloned())
        }

        fn supports_failure_receipts(&self) -> bool {
            true
        }

        fn persist_completed(&self, response: &BrokerExecuteResponse) -> Result<String> {
            if self.fail_completed {
                return Err(BrokerError::Storage(
                    "injected completed-response persistence failure".to_string(),
                ));
            }
            let encoded = canonical_json_bytes(response).map_err(|error| {
                BrokerError::Storage(format!("test completed response: {error}"))
            })?;
            if encoded
                .windows(self.canary.len())
                .any(|window| window == self.canary.as_slice())
            {
                return Err(BrokerError::Invariant(
                    "credential crossed into a completed response".to_string(),
                ));
            }
            let reference = self.persist(&response.receipt)?;
            if reference != response.receipt_reference {
                return Err(BrokerError::Invariant(
                    "test completed response reference is misbound".to_string(),
                ));
            }
            let mut completed = self.completed.lock().test_expect("completed lock");
            if let Some(existing) = completed.get(&response.evidence.attempt_id) {
                if existing != response {
                    return Err(BrokerError::Conflict(
                        "test attempt has a different completed response".to_string(),
                    ));
                }
            } else {
                completed.insert(response.evidence.attempt_id.clone(), response.clone());
            }
            Ok(reference)
        }

        fn load_completed(&self, attempt_id: &str) -> Result<Option<BrokerExecuteResponse>> {
            Ok(self
                .completed
                .lock()
                .test_expect("completed lock")
                .get(attempt_id)
                .cloned())
        }

        fn supports_completed_replay(&self) -> bool {
            true
        }
    }

    struct FailFirstSigningBackend {
        keypair: Keypair,
        fail_next: AtomicBool,
    }

    impl SigningBackend for FailFirstSigningBackend {
        fn algorithm(&self) -> SigningAlgorithm {
            self.keypair.public_key().algorithm()
        }

        fn public_key(&self) -> PublicKey {
            self.keypair.public_key()
        }

        fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<Signature> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(CoreError::InvalidSignature(
                    "injected first receipt-signing failure".to_string(),
                ));
            }
            Ok(self.keypair.sign(message))
        }
    }

    struct Fixture {
        service: Arc<BrokerService>,
        issuer: Keypair,
        audit_trusted_issuer: PublicKey,
        caller: Keypair,
        backend: Arc<EncryptedBlobSecretBackend>,
        provider: Arc<GenericCredentialProvider>,
        https: Arc<GenericHttpsExecutor>,
        authority: Arc<AtomicAuthority>,
        attempts: Arc<SqliteAttemptStore>,
        observed_authorizations: Arc<Mutex<Vec<Vec<u8>>>>,
        receipts: Arc<Mutex<Vec<Vec<u8>>>>,
        live_authority_calls: Arc<AtomicU64>,
        live_authority_unavailable: Arc<AtomicBool>,
        resolver_calls: Arc<AtomicU64>,
        migration_enforcer: Arc<crate::migration::TestBrokerMigrationEnforcer>,
        canary: Vec<u8>,
        audit_admin: Arc<GovernedAdminAuthorizer>,
        audit_admin_path: std::path::PathBuf,
        audit_approver: Keypair,
        audit_subject: PublicKey,
        audit_runner: Arc<dyn SigningBackend>,
        audit_runner_key: PublicKey,
        audit_authority: PublicKey,
        audit_receipt_signer: PublicKey,
        audit_approval_sequence: AtomicU64,
        _audit_directory: tempfile::TempDir,
    }

    struct FixtureServiceOptions {
        maximum_executions: u32,
        fail_transport: bool,
        deny_capture: bool,
        receipt_signer: Arc<dyn SigningBackend>,
    }

    struct AuditClock;

    impl crate::provision::AdminClock for AuditClock {
        fn now_unix_seconds(&self) -> Result<u64> {
            Ok(20)
        }
    }

    fn fixture(maximum_executions: u32, fail_transport: bool, deny_capture: bool) -> Fixture {
        let attempts = Arc::new(SqliteAttemptStore::open_in_memory().test_expect("attempt store"));
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let receipt_sink = Arc::new(InspectingReceiptSink {
            canary: b"unique-service-credential-canary".to_vec(),
            receipts: Arc::clone(&receipts),
            failures: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(BTreeMap::new()),
            failure_persist_entered: None,
            failure_persist_release: None,
            fail_completed: false,
        });
        fixture_with_stores(
            maximum_executions,
            fail_transport,
            deny_capture,
            attempts,
            receipt_sink,
            receipts,
        )
    }

    fn fixture_with_stores(
        maximum_executions: u32,
        fail_transport: bool,
        deny_capture: bool,
        attempts: Arc<SqliteAttemptStore>,
        receipt_sink: Arc<dyn BrokerReceiptSink>,
        receipts: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> Fixture {
        fixture_with_receipt_signer(
            FixtureServiceOptions {
                maximum_executions,
                fail_transport,
                deny_capture,
                receipt_signer: Arc::new(Ed25519Backend::new(Keypair::from_seed(&[3; 32]))),
            },
            attempts,
            receipt_sink,
            receipts,
        )
    }

    fn fixture_with_receipt_signer(
        options: FixtureServiceOptions,
        attempts: Arc<SqliteAttemptStore>,
        receipt_sink: Arc<dyn BrokerReceiptSink>,
        receipts: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> Fixture {
        let FixtureServiceOptions {
            maximum_executions,
            fail_transport,
            deny_capture,
            receipt_signer,
        } = options;
        let canary = b"unique-service-credential-canary".to_vec();
        let audit_directory = tempfile::tempdir().test_expect("audit admin directory");
        let audit_admin_path = std::fs::canonicalize(audit_directory.path())
            .test_expect("canonicalize audit admin directory")
            .join("audit-admin.sqlite3");
        let audit_approver = Keypair::from_seed(&[61; 32]);
        let audit_subject = Keypair::from_seed(&[62; 32]).public_key();
        let audit_runner: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[63; 32])));
        let audit_runner_key = audit_runner.public_key();
        let audit_receipt_signer = receipt_signer.public_key();
        let audit_authority_broker_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[71; 32])));
        let audit_authority_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[72; 32])));
        let audit_admin = Arc::new(
            GovernedAdminAuthorizer::open(
                &audit_admin_path,
                crate::provision::GovernedAdminPolicy {
                    trusted_approvers: vec![audit_approver.public_key()],
                    subject: audit_subject.clone(),
                    threshold: 1,
                    maximum_token_lifetime_seconds: 300,
                },
                receipt_signer.public_key(),
                Arc::new(AuditClock),
            )
            .test_expect("audit admin authorizer"),
        );
        let backend = Arc::new(
            EncryptedBlobSecretBackend::open_in_memory_for_test("tenant-a", [7; 32])
                .test_expect("backend"),
        );
        backend
            .provision(
                &CredentialRef {
                    provider: "generic-https".to_string(),
                    credential_id: "credential-a".to_string(),
                    version: 1,
                },
                &canary,
            )
            .test_expect("provision");
        let observed_authorizations = Arc::new(Mutex::new(Vec::new()));
        let resolver_calls = Arc::new(AtomicU64::new(0));
        let transport = Arc::new(ObservingTransport {
            observed_authorizations: Arc::clone(&observed_authorizations),
            fail: fail_transport,
            redirect: false,
        });
        let https = Arc::new(GenericHttpsExecutor::new(
            Arc::new(PublicResolver {
                calls: Arc::clone(&resolver_calls),
            }),
            transport,
            NetworkPolicy::production(),
        ));
        let authority = Arc::new(AtomicAuthority::new(deny_capture));
        let live_authority_calls = Arc::new(AtomicU64::new(0));
        let live_authority_unavailable = Arc::new(AtomicBool::new(false));
        let issuer = Keypair::from_seed(&[1; 32]);
        let audit_trusted_issuer = issuer.public_key();
        let caller = Keypair::from_seed(&[2; 32]);
        let provider = Arc::new(
            GenericCredentialProvider::new(
                "generic-bearer".to_string(),
                1,
                CredentialPlacement::BearerAuthorization,
            )
            .test_expect("provider"),
        );
        let migration_enforcer = crate::migration::TestBrokerMigrationEnforcer::new(vec![
            "generic-https".to_string(),
        ]);
        let service = BrokerService::new_for_test(
            BrokerServiceConfig {
                audience: "broker-service".to_string(),
                parent_audience: "broker-parent".to_string(),
                maximum_clock_skew_seconds: 2,
                maximum_liveness_snapshot_age_seconds: 5,
                maximum_revocation_snapshot_age_seconds: 5,
            },
            attempts.clone(),
            BrokerServiceAuthorityBundle {
                trusted_issuer: issuer.public_key(),
                backend: Arc::clone(&backend),
                provider: Arc::clone(&provider),
                https: Arc::clone(&https),
                budget: authority.clone(),
                liveness: Arc::new(LiveAuthority {
                    calls: Arc::clone(&live_authority_calls),
                    unavailable: Arc::clone(&live_authority_unavailable),
                    broker_signer: Arc::clone(&audit_authority_broker_signer),
                    authority_signer: Arc::clone(&audit_authority_signer),
                }),
                revocations: Arc::new(LiveRevocations {
                    calls: Arc::clone(&live_authority_calls),
                    unavailable: Arc::clone(&live_authority_unavailable),
                    broker_signer: audit_authority_broker_signer,
                    authority_signer: Arc::clone(&audit_authority_signer),
                }),
                receipt_sink,
                receipt_signer,
                migration_enforcer: migration_enforcer.clone(),
            },
        )
        .test_expect("service");
        let _ = maximum_executions;
        Fixture {
            service: Arc::new(service),
            issuer,
            audit_trusted_issuer,
            caller,
            backend,
            provider,
            https,
            authority,
            attempts,
            observed_authorizations,
            receipts,
            live_authority_calls,
            live_authority_unavailable,
            resolver_calls,
            migration_enforcer,
            canary,
            audit_admin,
            audit_admin_path,
            audit_approver,
            audit_subject,
            audit_runner,
            audit_runner_key,
            audit_authority: audit_authority_signer.public_key(),
            audit_receipt_signer,
            audit_approval_sequence: AtomicU64::new(0),
            _audit_directory: audit_directory,
        }
    }

    fn governed_audit_authorization(
        fixture: &Fixture,
        intent_digest: &str,
    ) -> AdminAuthorization {
        let sequence = fixture
            .audit_approval_sequence
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        let token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("broker-audit-approval-{sequence}"),
                approver: fixture.audit_approver.public_key(),
                subject: fixture.audit_subject.clone(),
                governed_intent_hash: intent_digest.to_string(),
                threshold_proposal_hash: Some("ab".repeat(32)),
                request_id: format!("broker-audit-request-{sequence}"),
                issued_at: 19,
                expires_at: 80,
                decision: GovernedApprovalDecision::Approved,
            },
            &fixture.audit_approver,
        )
        .test_expect("sign governed audit approval");
        let envelope = crate::provision::GovernedAdminAuthorizationEnvelope::new(vec![token])
            .test_expect("governed audit envelope");
        AdminAuthorization::new(
            envelope
                .canonical_bytes()
                .test_expect("canonical governed audit envelope"),
        )
        .test_expect("governed audit authorization")
    }

    fn authorized_audit(
        fixture: &Fixture,
        request: &BrokerExecuteRequest,
        reference: &crate::audit::BrokerAuditReferenceRequest,
        audit_id: &str,
        now_unix_seconds: u64,
    ) -> (
        crate::audit::VerifiedBrokerAuditRunnerAuthorization,
        AdminAuthorization,
        crate::audit::SignedBrokerAuditRunnerAuthorization,
    ) {
        let runner = crate::audit::SignedBrokerAuditRunnerAuthorization::sign(
            crate::audit::BrokerAuditRunnerAuthorizationBody::for_request(
                request,
                reference,
                crate::audit::BrokerAuditRunnerScope {
                    audit_id,
                    deployment_id: "test-deployment",
                    broker_instance_id: "test-broker-instance",
                    tenant_scope: "tenant-a",
                    runner_id: "test-enterprise-runner",
                    reference_source: "legacy-provider-observation",
                    revocation_authority_domain: "combined-authority",
                },
                now_unix_seconds.saturating_sub(1),
                now_unix_seconds + 60,
            )
            .test_expect("audit runner authorization body"),
            fixture.audit_runner.as_ref(),
        )
        .test_expect("sign audit runner authorization");
        let verified = crate::audit::verify_broker_audit_runner_authorization(
            &runner,
            request,
            reference,
            crate::audit::BrokerAuditRunnerTrust {
                deployment_id: "test-deployment",
                broker_instance_id: "test-broker-instance",
                tenant_scope: "tenant-a",
                runner_id: "test-enterprise-runner",
                trusted_runner: &fixture.audit_runner.public_key(),
            },
            now_unix_seconds,
        )
        .test_expect("verify audit runner authorization");
        let admin = governed_audit_authorization(fixture, verified.governed_intent_sha256());
        (verified, admin, runner)
    }

    fn execution(
        fixture: &Fixture,
        invocation_index: usize,
        maximum_executions: u32,
    ) -> (BrokerExecuteRequest, TrustedExecutionContext) {
        let destination = BrokerDestination::parse("https://example.com/v1", "POST", false)
            .test_expect("destination");
        let request = BrokerRequest {
            destination: destination.clone(),
            headers: Vec::new(),
            body: b"request-body".to_vec(),
            approved_preview_sha256: None,
            options: CallerOptions {
                timeout_ms: 1_000,
                streaming: false,
                response_limit_bytes: 1_024,
            },
        };
        let capability = issue_capability(
            BrokerCapabilityBody {
                schema: BROKER_CAPABILITY_SCHEMA.to_string(),
                issuer: fixture.issuer.public_key(),
                capability_id: "broker-capability".to_string(),
                parent_capability_id: "parent-capability".to_string(),
                subject: fixture.caller.public_key(),
                audience: "broker-service".to_string(),
                issued_at_unix_seconds: 10,
                not_before_unix_seconds: 10,
                expires_at_unix_seconds: 1_000,
                credential: CredentialRef {
                    provider: "generic-https".to_string(),
                    credential_id: "credential-a".to_string(),
                    version: 1,
                },
                provider_adapter_id: "generic-bearer".to_string(),
                provider_adapter_version: 1,
                destination,
                constraints: RequestConstraints {
                    allowed_caller_headers: Vec::new(),
                    provider_owned_headers: vec!["authorization".to_string()],
                    maximum_body_bytes: 1_024,
                    required_body_sha256: body_digest(&request.body),
                    required_preview_sha256: None,
                    redirect_policy: RedirectPolicy::Disabled,
                    maximum_response_bytes: 1_024,
                    streaming_allowed: false,
                    maximum_timeout_ms: 1_000,
                },
                broker_quota_key_id: "broker-quota".to_string(),
                maximum_executions,
                consumption: AttemptConsumption::CaptureBeforeDispatch,
                revocation_id: "broker-revocation".to_string(),
                proof: ProofBinding {
                    mode: ProofMode::PublicKey,
                    caller_public_key: fixture.caller.public_key(),
                    nonce_ttl_seconds: 30,
                },
            },
            &Ed25519Backend::new(fixture.issuer.clone()),
            true,
        )
        .test_expect("capability");
        let proof = issue_request_proof(
            &capability,
            &request,
            format!("nonce-{invocation_index:016}"),
            20,
            &fixture.caller,
        )
        .test_expect("proof");
        let execute = BrokerExecuteRequest {
            schema: BROKER_EXECUTE_SCHEMA.to_string(),
            invocation_id: format!("invocation-{invocation_index}"),
            capability,
            proof,
            request,
        };
        let admission_operation_id = format!("kernel-admission-operation-{invocation_index}");
        let quotas = vec![
            ExecutionQuota {
                key_id: "broker-quota".to_string(),
                maximum_executions,
            },
            ExecutionQuota {
                key_id: "parent-grant-quota".to_string(),
                maximum_executions: 100,
            },
        ];
        let registration = test_attempt_registration(
            &execute,
            &admission_operation_id,
            &quotas,
            &"e".repeat(64),
            "combined-authority",
        );
        let trusted = TrustedExecutionContext {
            admission_operation_id,
            prepared_dispatch_id: prepared_dispatch_id(&registration, &execute)
                .test_expect("prepared dispatch id"),
            quotas,
            authority_metadata_digest: "e".repeat(64),
            revocation_authority_domain: "combined-authority".to_string(),
            source_receipt_ids: vec!["source-receipt-parent-admission".to_string()],
        };
        (execute, trusted)
    }

    fn test_attempt_registration(
        request: &BrokerExecuteRequest,
        admission_operation_id: &str,
        quotas: &[ExecutionQuota],
        authority_metadata_digest: &str,
        revocation_authority_domain: &str,
    ) -> AttemptRegistration {
        let request_digest = broker_request_digest(request).test_expect("request digest");
        let ids = derive_attempt_ids_for_operation(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
            admission_operation_id,
        )
        .test_expect("attempt ids");
        AttemptRegistration {
            ids,
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            request_digest,
            request_canonical_digest: broker_execute_request_registration_digest(request)
                .test_expect("canonical request digest"),
            proof_digest: proof_digest(&request.proof).test_expect("proof digest"),
            proof_key_id: request.proof.body.authority_key.to_hex(),
            proof_nonce: request.proof.body.nonce.clone(),
            nonce_expires_at_unix_seconds: request
                .proof
                .body
                .issued_at_unix_seconds
                .checked_add(request.capability.body.proof.nonce_ttl_seconds)
                .test_expect("nonce expiry"),
            quotas: quotas.to_vec(),
            authority_metadata_digest: authority_metadata_digest.to_string(),
            revocation_authority_domain: revocation_authority_domain.to_string(),
        }
    }

    fn register_prepared_execution(
        fixture: &Fixture,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        now_unix_seconds: u64,
    ) -> crate::store::AttemptIds {
        let registration = test_attempt_registration(
            request,
            &trusted.admission_operation_id,
            &trusted.quotas,
            &trusted.authority_metadata_digest,
            &trusted.revocation_authority_domain,
        );
        let ids = registration.ids.clone();
        fixture
            .service
            .register_attempt(&registration, request, now_unix_seconds)
            .test_expect("register execution");
        let authorization = fixture
            .authority
            .authorize_execution_hold(&AuthorizeExecutionHoldRequest {
                operation_id: ids.operation_id.clone(),
                invocation_id: request.invocation_id.clone(),
                parent_capability_id: request.capability.body.parent_capability_id.clone(),
                broker_capability_id: request.capability.body.capability_id.clone(),
                hold_id: ids.hold_id.clone(),
                authorize_event_id: ids.authorize_event_id.clone(),
                quotas: trusted.quotas.clone(),
                authority_metadata_digest: trusted.authority_metadata_digest.clone(),
            })
            .test_expect("kernel authorizes execution");
        if authorization == ExecutionHoldState::Held {
            fixture
                .service
                .prepare_dispatch(&registration, request, now_unix_seconds)
                .test_expect("prepare broker dispatch");
        }
        ids
    }

    fn register_execution(
        fixture: &Fixture,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
        now_unix_seconds: u64,
    ) {
        let ids = register_prepared_execution(fixture, request, trusted, now_unix_seconds);
        if matches!(
            fixture
                .authority
                .query_execution_hold(&execution_hold_query_for_test(request, &ids))
                .test_expect("query prepared authority state"),
            ExecutionHoldState::Held
        ) {
            let revocation_set = CanonicalBrokerRevocationSet::new(
                &request.capability.body.parent_capability_id,
                &["delegation-ancestor".to_string()],
                &request.capability.body.capability_id,
                &request.capability.body.revocation_id,
            )
            .test_expect("revocation set");
            let _ = fixture
                .authority
                .capture_execution_hold(&CaptureExecutionHoldRequest {
                    operation_id: ids.operation_id,
                    invocation_id: request.invocation_id.clone(),
                    parent_capability_id: request.capability.body.parent_capability_id.clone(),
                    broker_capability_id: request.capability.body.capability_id.clone(),
                    hold_id: ids.hold_id,
                    capture_event_id: ids.capture_event_id,
                    revocation_ids: revocation_set.ids().to_vec(),
                    revocation_set_digest: revocation_set.digest().to_string(),
                    authorization_artifact_digest: capability_digest(&request.capability)
                        .test_expect("capability digest"),
                    authority_metadata_digest: trusted.authority_metadata_digest.clone(),
                });
        }
    }

    fn execution_hold_query_for_test(
        request: &BrokerExecuteRequest,
        ids: &crate::store::AttemptIds,
    ) -> QueryExecutionHoldRequest {
        QueryExecutionHoldRequest {
            operation_id: ids.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            hold_id: ids.hold_id.clone(),
            authorize_event_id: ids.authorize_event_id.clone(),
            reverse_event_id: ids.reverse_event_id.clone(),
            capture_event_id: ids.capture_event_id.clone(),
        }
    }

    fn captured_attempt_evidence(
        fixture: &Fixture,
        request: &BrokerExecuteRequest,
        trusted: &TrustedExecutionContext,
    ) -> (crate::store::AttemptIds, AttemptTransitionEvidence) {
        let request_digest = broker_request_digest(request).test_expect("request digest");
        let ids = derive_attempt_ids_for_operation(
            &request.capability.body.capability_id,
            &request.invocation_id,
            &request.proof.body.nonce,
            &request_digest,
            &trusted.admission_operation_id,
        )
        .test_expect("attempt ids");
        let state = fixture
            .authority
            .query_execution_hold(&QueryExecutionHoldRequest {
                operation_id: ids.operation_id.clone(),
                invocation_id: request.invocation_id.clone(),
                parent_capability_id: request.capability.body.parent_capability_id.clone(),
                broker_capability_id: request.capability.body.capability_id.clone(),
                hold_id: ids.hold_id.clone(),
                authorize_event_id: ids.authorize_event_id.clone(),
                reverse_event_id: ids.reverse_event_id.clone(),
                capture_event_id: ids.capture_event_id.clone(),
            })
            .test_expect("query captured hold");
        let ExecutionHoldState::Captured(commit) = state else {
            panic!("expected captured authority state");
        };
        (
            ids,
            AttemptTransitionEvidence {
                revocation_set_digest: Some(commit.checked_revocation_set_digest),
                budget_commit_index: Some(commit.budget_commit_index),
                revocation_commit_index: Some(commit.revocation_commit_index),
                authority_commit_index: Some(commit.authority_commit_index),
                leader_epoch: Some(commit.leader_epoch),
                response_digest: None,
            },
        )
    }
