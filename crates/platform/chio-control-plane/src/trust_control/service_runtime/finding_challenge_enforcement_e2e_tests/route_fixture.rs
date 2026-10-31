use super::*;
use crate::trust_control::BlockingLane;

pub(super) fn challenge_route_state(
    deployment: &Deployment,
    executor: Arc<dyn FindingChallengeSubmissionExecutor>,
) -> TrustServiceState {
    let config = TrustServiceConfig {
        access: crate::trust_control::caller_credentials::tests::test_access(
            "challenge-service-secret",
        ),
        finding_market: Some(market_config()),
        ..TrustServiceConfig::for_tests()
    };
    TrustServiceState {
        finding_challenge_clock: Arc::new(chio_security_types::clock::SystemClock),
        config,
        authority_keyring: None,
        authority_keyring_seed_path: None,
        stop: crate::trust_control::TrustStop::for_authority(Some(&deployment._authority)),
        joint_authority_store: Some(Arc::clone(&deployment._authority)),
        fiscal_runtime: None,
        budget_store: None,
        revocation_store: None,
        passport_revocation_oracle: None,
        partner_revocation_door: Arc::new(crate::trust_control::PartnerRevocationDoor::strict()),
        receipt_store: None,
        receipt_query_snapshots: None,
        receipt_query_lane: Arc::new(tokio::sync::Semaphore::new(4)),
        evidence_export_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        federation_admission_rate_limiter: Arc::new(Mutex::new(
            FederationAdmissionRateLimiter::default(),
        )),
        cluster: None,
        peer_nonces: None,
        cluster_progress: None,
        leader_forward_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        authority_health_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        authority_inspection_lane: Arc::new(tokio::sync::Semaphore::new(8)),
        operator_registry_write_lane: BlockingLane::new("operator_registry_write", 2),
        public_passport_issuance_lane: BlockingLane::new("public_passport_issuance", 2),
        wallet_entitlement_lane: crate::trust_control::ingress_lanes::wallet_entitlement_lane(),
        public_passport_challenge_lane: Arc::new(tokio::sync::Semaphore::new(
            crate::trust_control::report_rendering::PUBLIC_PASSPORT_CHALLENGE_PERMITS,
        )),
        finding_rail: Some(deployment.rail.clone()),
        finding_purchase_executor: None,
        finding_purchase_execution_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_proof_egress_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_seller_submission_executor: None,
        finding_seller_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_challenge_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_authority_status_resolver: Some(Arc::new(TestAuthorityStatusResolver::live())),
        finding_challenge_executor: Some(executor),
    }
}
