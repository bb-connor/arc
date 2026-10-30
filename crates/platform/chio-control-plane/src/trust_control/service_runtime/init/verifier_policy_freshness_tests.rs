//! A running trust-control service resolves verifier policy references from
//! the registry file each request reads, so an operator mutation governs the
//! next challenge and verification without a restart.

use super::super::client::build_client;
use super::*;
use crate::ControlPlaneError;
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, respond_to_passport_presentation_challenge,
    AttestationWindow, ChioCredentialEvidence, PassportPresentationChallenge,
    PassportVerifierPolicy,
};
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "service-token";
const VERIFIER: &str = "https://verifier.example.test";
const POLICY_ID: &str = "admission";

struct RunningService {
    _directory: tempfile::TempDir,
    policies: PathBuf,
    client: TrustControlClient,
    server: tokio::task::JoinHandle<Result<(), CliError>>,
    _runtime: tokio::runtime::Runtime,
}

impl RunningService {
    fn start(initial: Option<&VerifierPolicyRegistry>) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let policies = directory.path().join("verifier-policies.json");
        if let Some(registry) = initial {
            std::fs::write(&policies, chio_core::canonical_json_bytes(registry)?)?;
        }
        let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = reservation.local_addr()?;
        drop(reservation);
        let config = service_config(
            address,
            directory.path().join("revocations.db"),
            policies.clone(),
            directory.path().join("verifier-challenges.sqlite3"),
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let server = runtime.spawn(serve_async(config, None, None, None, None, None, None));
        let client = build_client(&format!("http://127.0.0.1:{}", address.port()), TOKEN)?;
        (0..500)
            .find(|_| {
                let ready = client.list_verifier_policies().is_ok();
                if !ready {
                    std::thread::sleep(Duration::from_millis(20));
                }
                ready
            })
            .ok_or("the trust service never answered")?;
        Ok(Self {
            _directory: directory,
            policies,
            client,
            server,
            _runtime: runtime,
        })
    }

    fn create_challenge(&self) -> Result<PassportPresentationChallenge, CliError> {
        Ok(self
            .client
            .create_passport_challenge(&CreatePassportChallengeRequest {
                verifier: VERIFIER.to_string(),
                ttl_seconds: 600,
                issuers: Vec::new(),
                max_credentials: None,
                policy_id: Some(POLICY_ID.to_string()),
                policy: None,
            })?
            .challenge)
    }
}

impl Drop for RunningService {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct Holder {
    keypair: Keypair,
    passport: AgentPassport,
}

impl Holder {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let now = unix_timestamp_now()?;
        let keypair = Keypair::from_seed(&[71; 32]);
        let scorecard = chio_reputation::compute_local_scorecard(
            &keypair.public_key().to_hex(),
            now,
            &chio_reputation::LocalReputationCorpus::default(),
            &chio_reputation::ReputationConfig::default(),
        );
        let credential = issue_reputation_credential(
            &Keypair::from_seed(&[72; 32]),
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
        )?;
        let subject = credential.unsigned.credential_subject.id.clone();
        let passport = build_agent_passport(&subject, vec![credential])?;
        Ok(Self { keypair, passport })
    }

    fn answer(
        &self,
        challenge: &PassportPresentationChallenge,
    ) -> Result<VerifyPassportChallengeRequest, Box<dyn std::error::Error>> {
        Ok(VerifyPassportChallengeRequest {
            presentation: respond_to_passport_presentation_challenge(
                &self.keypair,
                &self.passport,
                challenge,
                unix_timestamp_now()?,
            )?,
            expected_challenge: None,
        })
    }
}

fn service_config(
    listen: std::net::SocketAddr,
    revocation_db_path: PathBuf,
    verifier_policies_file: PathBuf,
    verifier_challenge_db_path: PathBuf,
) -> TrustServiceConfig {
    TrustServiceConfig {
        transport: Default::default(),
        listen,
        access: crate::trust_control::caller_credentials::tests::test_access(TOKEN),
        receipt_db_path: None,
        receipt_query_snapshot_quota_bytes: 2_147_483_648,
        revocation_db_path: Some(revocation_db_path),
        authority_seed_path: None,
        authority_db_path: None,
        authority_keyring_config_path: None,
        authority_keyring_receipt_anchor_root: None,
        budget_db_path: None,
        cluster_peer_replay_db_path: None,
        joint_authority_db_path: None,
        fiscal_runtime: None,
        enterprise_providers_file: None,
        federation_policies_file: None,
        scim_lifecycle_file: None,
        verifier_policies_file: Some(verifier_policies_file),
        verifier_challenge_db_path: Some(verifier_challenge_db_path),
        passport_statuses_file: None,
        revocation_partners_file: None,
        passport_issuance_offers_file: None,
        certification_registry_file: None,
        certification_discovery_file: None,
        issuance_policy: None,
        runtime_assurance_policy: None,
        advertise_url: None,
        allow_local_peer_urls: true,
        certification_public_metadata_ttl_seconds: 300,
        cluster_sync_interval: Duration::from_millis(25),
        authority_replication_max_future_skew_seconds: 0,
        roster_policy: None,
        capital_authority: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: None,
    }
}

fn signed_policy(
    policy: PassportVerifierPolicy,
) -> Result<SignedPassportVerifierPolicy, Box<dyn std::error::Error>> {
    let now = unix_timestamp_now()?;
    Ok(chio_credentials::create_signed_passport_verifier_policy(
        &Keypair::from_seed(&[73; 32]),
        POLICY_ID,
        VERIFIER,
        now.saturating_sub(60),
        now.saturating_add(3_600),
        policy,
    )?)
}

fn registry_with(
    document: SignedPassportVerifierPolicy,
) -> Result<VerifierPolicyRegistry, Box<dyn std::error::Error>> {
    let mut registry = VerifierPolicyRegistry::default();
    registry.upsert(document)?;
    Ok(registry)
}

fn refusal<T>(
    outcome: Result<T, CliError>,
) -> Result<(u16, serde_json::Value), Box<dyn std::error::Error>> {
    match outcome {
        Err(CliError::ControlPlane(ControlPlaneError::Rejected { status, body })) => {
            Ok((status, serde_json::from_str(&body)?))
        }
        Err(other) => Err(other.into()),
        Ok(_) => Err("the service accepted a request it must refuse".into()),
    }
}

#[test]
fn a_policy_deleted_after_startup_refuses_the_next_challenge() -> TestResult {
    let initial = registry_with(signed_policy(PassportVerifierPolicy::default())?)?;
    let service = RunningService::start(Some(&initial))?;
    service.client.delete_verifier_policy(POLICY_ID)?;
    let expected = VerifierPolicyRegistry::load(&service.policies)?
        .active_policy(POLICY_ID, unix_timestamp_now()?)
        .err()
        .ok_or("the deleted policy is still on disk")?;
    assert_eq!(
        refusal(service.create_challenge())?,
        (400, serde_json::json!({"error": expected.to_string()}))
    );
    Ok(())
}

#[test]
fn a_policy_added_after_startup_serves_the_next_challenge() -> TestResult {
    let service = RunningService::start(None)?;
    service.client.upsert_verifier_policy(
        POLICY_ID,
        &signed_policy(PassportVerifierPolicy::default())?,
    )?;
    let challenge = service.create_challenge()?;
    assert_eq!(
        challenge.policy_ref.map(|reference| reference.policy_id),
        Some(POLICY_ID.to_string())
    );
    Ok(())
}

#[test]
fn a_policy_tightened_after_startup_denies_the_next_verification() -> TestResult {
    let initial = registry_with(signed_policy(PassportVerifierPolicy::default())?)?;
    let service = RunningService::start(Some(&initial))?;
    let holder = Holder::new()?;

    let control = service.create_challenge()?;
    let accepted = service
        .client
        .verify_passport_challenge(&holder.answer(&control)?)?;
    assert!(
        accepted.accepted,
        "the permissive policy refused the holder"
    );
    assert_eq!(
        accepted.policy_source.as_deref(),
        Some("registry:admission")
    );

    let challenge = service.create_challenge()?;
    let tightened = PassportVerifierPolicy {
        min_receipt_count: Some(1),
        ..PassportVerifierPolicy::default()
    };
    service
        .client
        .upsert_verifier_policy(POLICY_ID, &signed_policy(tightened.clone())?)?;
    let denied = service
        .client
        .verify_passport_challenge(&holder.answer(&challenge)?)?;
    assert!(
        !denied.accepted,
        "a verification after the tightening was judged by the startup policy"
    );
    assert_eq!(denied.policy_source.as_deref(), Some("registry:admission"));
    let expected = chio_credentials::evaluate_agent_passport(
        &holder.passport,
        denied.verified_at,
        &tightened,
    )?;
    assert_eq!(denied.policy_evaluation, Some(expected));
    Ok(())
}

#[test]
fn a_registry_corrupted_after_startup_refuses_challenges_and_verifications() -> TestResult {
    let initial = registry_with(signed_policy(PassportVerifierPolicy::default())?)?;
    let service = RunningService::start(Some(&initial))?;
    let holder = Holder::new()?;
    let challenge = service.create_challenge()?;

    let mut tampered = initial.clone();
    let document = tampered
        .policies
        .get_mut(POLICY_ID)
        .ok_or("fixture policy is missing")?;
    document.body.policy.min_receipt_count = Some(0);
    std::fs::write(
        &service.policies,
        chio_core::canonical_json_bytes(&tampered)?,
    )?;
    let expected = VerifierPolicyRegistry::load(&service.policies)
        .err()
        .ok_or("the tampered registry loaded")?
        .to_string();

    assert_eq!(
        refusal(service.create_challenge())?,
        (409, serde_json::json!({"error": expected}))
    );
    assert_eq!(
        refusal(
            service
                .client
                .verify_passport_challenge(&holder.answer(&challenge)?)
        )?,
        (400, serde_json::json!({"error": expected}))
    );
    Ok(())
}
