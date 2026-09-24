// RPC completion can cross a clock tick after the caller sampled request time.
struct AuthorityTestClock {
    now: AtomicU64,
    unavailable: AtomicBool,
}
impl crate::daemon::DaemonClock for AuthorityTestClock {
    fn now_unix_seconds(&self) -> Result<u64> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(BrokerError::AuthorityUnavailable(
                "clock unavailable".into(),
            ));
        }
        Ok(self.now.load(Ordering::SeqCst))
    }
}

struct AdvancingAuthority {
    clock: Arc<AuthorityTestClock>,
    liveness: Arc<dyn CapabilityLiveness>,
    revocations: Arc<dyn BrokerRevocations>,
    mode: &'static str,
}
impl CapabilityLiveness for AdvancingAuthority {
    fn verify_live_parent(
        &self,
        request: &CapabilityLivenessRequest,
    ) -> Result<LiveParentCapability> {
        let mut parent = self.liveness.verify_live_parent(request)?;
        parent.verified_at_unix_seconds = self.clock.now.fetch_add(1, Ordering::SeqCst) + 1;
        match self.mode {
            "future" => parent.verified_at_unix_seconds += 1,
            "expired" => parent.expires_at_unix_seconds = parent.verified_at_unix_seconds,
            "expires_during_revocation" => {
                parent.expires_at_unix_seconds = parent.verified_at_unix_seconds + 1;
            }
            "rollback" => {
                self.clock.now.store(19, Ordering::SeqCst);
            }
            "unavailable" => self.clock.unavailable.store(true, Ordering::SeqCst),
            _ => {}
        }
        Ok(parent)
    }
    fn verify_live_parent_with_audit_evidence(
        &self,
        request: &CapabilityLivenessRequest,
    ) -> Result<crate::authority_ipc::VerifiedAuthorityExchange> {
        let parent = self.verify_live_parent(request)?;
        crate::authority_ipc::sign_test_authority_exchange(
            crate::authority_ipc::AuthorityOperation::VerifyLiveParent(request.clone()),
            crate::authority_ipc::AuthorityResult::LiveParent(parent),
            self.clock.now.load(Ordering::SeqCst),
            &Ed25519Backend::new(Keypair::from_seed(&[71; 32])),
            &Ed25519Backend::new(Keypair::from_seed(&[72; 32])),
            2,
        )
    }
}
impl BrokerRevocations for AdvancingAuthority {
    fn check_broker_revocation(
        &self,
        request: &BrokerRevocationRequest,
    ) -> Result<BrokerRevocationSnapshot> {
        let mut snapshot = self.revocations.check_broker_revocation(request)?;
        snapshot.observed_at_unix_seconds = self.clock.now.fetch_add(1, Ordering::SeqCst) + 1;
        if self.mode == "future_revocation" {
            snapshot.observed_at_unix_seconds += 1;
        }
        Ok(snapshot)
    }
    fn check_broker_revocation_with_audit_evidence(
        &self,
        request: &BrokerRevocationRequest,
    ) -> Result<crate::authority_ipc::VerifiedAuthorityExchange> {
        let snapshot = self.check_broker_revocation(request)?;
        crate::authority_ipc::sign_test_authority_exchange(
            crate::authority_ipc::AuthorityOperation::CheckBrokerRevocation(request.clone()),
            crate::authority_ipc::AuthorityResult::Revocation(snapshot),
            self.clock.now.load(Ordering::SeqCst),
            &Ed25519Backend::new(Keypair::from_seed(&[71; 32])),
            &Ed25519Backend::new(Keypair::from_seed(&[72; 32])),
            2,
        )
    }
}

fn advancing_authority_fixture(mode: &'static str) -> Fixture {
    let mut fixture = fixture(1, false, false);
    let clock = Arc::new(AuthorityTestClock {
        now: AtomicU64::new(20),
        unavailable: AtomicBool::new(false),
    });
    let service = Arc::get_mut(&mut fixture.service).test_expect("unshared service");
    let authority = Arc::new(AdvancingAuthority {
        clock: clock.clone(),
        liveness: service.liveness.clone(),
        revocations: service.revocations.clone(),
        mode,
    });
    service.authority_clock = Some(clock);
    service.liveness = authority.clone();
    service.revocations = authority;
    fixture
}

#[test]
fn authority_rpc_completion_uses_current_trusted_time() {
    let fixture = advancing_authority_fixture("normal");
    let (request, _) = execution(&fixture, 210, 1);
    fixture
        .service
        .validate_request_authorities(&request, "combined-authority", 20, true)
        .test_expect("fresh responses produced after the request started");
    assert!(fixture
        .observed_authorizations
        .lock()
        .test_expect("provider observations")
        .is_empty());
}

#[test]
fn authority_rpc_completion_rejects_future_expired_and_unavailable_time() {
    for mode in [
        "future",
        "future_revocation",
        "expired",
        "expires_during_revocation",
        "rollback",
        "unavailable",
    ] {
        let fixture = advancing_authority_fixture(mode);
        let (request, _) = execution(&fixture, 211, 1);
        let error = fixture
            .service
            .validate_request_authorities(&request, "combined-authority", 20, true)
            .err()
            .test_expect("invalid authority observation must deny");
        if mode == "rollback" {
            assert!(error.to_string().contains("moved backwards"));
        } else if mode == "unavailable" {
            assert!(error.to_string().contains("clock unavailable"));
        }
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("provider observations")
            .is_empty());
    }
}

#[test]
fn authority_rpc_completion_time_is_bound_into_independently_verified_audit() {
    let fixture = advancing_authority_fixture("normal");
    let (request, _) = execution(&fixture, 212, 1);
    let (reference, precommitment) = audit_reference_for_execution(&fixture, &request, true);
    let (runner, admin, signed_runner) = authorized_audit(
        &fixture,
        &request,
        &reference,
        "audit-delayed-authority",
        20,
    );
    let completed = fixture
        .service
        .audit_compare_outbound_request(
            &request,
            reference,
            runner,
            &admin,
            fixture.audit_admin.as_ref(),
            20,
        )
        .test_expect("audit observes authority completion time");
    assert_eq!(completed.comparison.body.issued_at_unix_seconds, 22);
    let mut context = completed_audit_context(
        &request,
        "audit-delayed-authority",
        "legacy-provider-observation",
        &precommitment,
        audit_trust(&fixture),
    );
    context.expires_at_unix_seconds = 24;
    verify_completed_audit(&completed, &signed_runner, &admin, context)
        .test_expect("independent verification preserves original request times");
}
