//! A running trust-control service resolves verifier policy references from
//! the registry file each request reads, so an operator mutation governs the
//! next challenge and verification without a restart.

use super::*;
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, respond_to_passport_presentation_challenge,
    AttestationWindow, ChioCredentialEvidence, PassportPresentationVerification,
    PassportVerifierPolicy,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "service-token";
const VERIFIER: &str = "https://verifier.example.test";
const POLICY_ID: &str = "admission";

struct RunningService {
    _directory: tempfile::TempDir,
    policies: PathBuf,
    base: String,
    client: reqwest::Client,
    server: tokio::task::JoinHandle<Result<(), CliError>>,
}

impl RunningService {
    async fn start(
        initial: Option<&VerifierPolicyRegistry>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
        let server = tokio::spawn(serve_async(config, None, None, None, None, None, None));
        let service = Self {
            _directory: directory,
            policies,
            base: format!("http://127.0.0.1:{}", address.port()),
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: loopback harness for the spawned service.
            client: reqwest::Client::builder().no_proxy().build()?,
            server,
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(response) = service
                    .client
                    .get(service.url(PASSPORT_VERIFIER_POLICIES_PATH))
                    .bearer_auth(TOKEN)
                    // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: loopback harness for the spawned service.
                    .send()
                    .await
                {
                    if response.status() == reqwest::StatusCode::OK {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        Ok(service)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn policy_url(&self, policy_id: &str) -> String {
        self.url(&PASSPORT_VERIFIER_POLICY_PATH.replace("{policy_id}", policy_id))
    }

    async fn upsert(&self, document: &SignedPassportVerifierPolicy) -> TestResult {
        let response = self
            .client
            .put(self.policy_url(&document.body.policy_id))
            .bearer_auth(TOKEN)
            .json(document)
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: loopback harness for the spawned service.
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        Ok(())
    }

    async fn create_challenge(&self) -> Result<reqwest::Response, reqwest::Error> {
        self.client
            .post(self.url(PASSPORT_CHALLENGES_PATH))
            .bearer_auth(TOKEN)
            .json(&CreatePassportChallengeRequest {
                verifier: VERIFIER.to_string(),
                ttl_seconds: 600,
                issuers: Vec::new(),
                max_credentials: None,
                policy_id: Some(POLICY_ID.to_string()),
                policy: None,
            })
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: loopback harness for the spawned service.
            .send()
            .await
    }

    async fn challenge(
        &self,
    ) -> Result<chio_credentials::PassportPresentationChallenge, Box<dyn std::error::Error>> {
        let response = self.create_challenge().await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        Ok(response
            .json::<CreatePassportChallengeResponse>()
            .await?
            .challenge)
    }

    async fn verify(
        &self,
        holder: &Holder,
        challenge: &chio_credentials::PassportPresentationChallenge,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
        let presentation = respond_to_passport_presentation_challenge(
            &holder.keypair,
            &holder.passport,
            challenge,
            unix_timestamp_now()?,
        )?;
        Ok(self
            .client
            .post(self.url(PASSPORT_CHALLENGE_VERIFY_PATH))
            .bearer_auth(TOKEN)
            .json(&VerifyPassportChallengeRequest {
                presentation,
                expected_challenge: None,
            })
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: loopback harness for the spawned service.
            .send()
            .await?)
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
        service_token: TOKEN.to_string(),
        tenant_read_tokens: BTreeMap::new(),
        authority_workload_token: None,
        receipt_db_path: None,
        receipt_query_snapshot_quota_bytes: 2_147_483_648,
        revocation_db_path: Some(revocation_db_path),
        authority_seed_path: None,
        authority_db_path: None,
        authority_keyring_config_path: None,
        authority_keyring_receipt_anchor_root: None,
        budget_db_path: None,
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
        peer_urls: Vec::new(),
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

async fn error_body(response: reqwest::Response) -> Result<serde_json::Value, reqwest::Error> {
    response.json::<serde_json::Value>().await
}

#[tokio::test]
async fn a_policy_deleted_after_startup_refuses_the_next_challenge() -> TestResult {
    let initial = registry_with(signed_policy(PassportVerifierPolicy::default())?)?;
    let service = RunningService::start(Some(&initial)).await?;
    let deleted = service
        .client
        .delete(service.policy_url(POLICY_ID))
        .bearer_auth(TOKEN)
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: loopback harness for the spawned service.
        .send()
        .await?;
    assert_eq!(deleted.status(), reqwest::StatusCode::OK);
    let expected = VerifierPolicyRegistry::load(&service.policies)?
        .active_policy(POLICY_ID, unix_timestamp_now()?)
        .err()
        .ok_or("the deleted policy is still on disk")?;
    let response = service.create_challenge().await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        error_body(response).await?,
        serde_json::json!({"error": expected.to_string()})
    );
    Ok(())
}

#[tokio::test]
async fn a_policy_added_after_startup_serves_the_next_challenge() -> TestResult {
    let service = RunningService::start(None).await?;
    service
        .upsert(&signed_policy(PassportVerifierPolicy::default())?)
        .await?;
    let challenge = service.challenge().await?;
    assert_eq!(
        challenge.policy_ref.map(|reference| reference.policy_id),
        Some(POLICY_ID.to_string())
    );
    Ok(())
}

#[tokio::test]
async fn a_policy_tightened_after_startup_denies_the_next_verification() -> TestResult {
    let initial = registry_with(signed_policy(PassportVerifierPolicy::default())?)?;
    let service = RunningService::start(Some(&initial)).await?;
    let holder = Holder::new()?;

    let control = service.challenge().await?;
    let response = service.verify(&holder, &control).await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let accepted = response.json::<PassportPresentationVerification>().await?;
    assert!(
        accepted.accepted,
        "the permissive policy refused the holder"
    );
    assert_eq!(
        accepted.policy_source.as_deref(),
        Some("registry:admission")
    );

    let challenge = service.challenge().await?;
    let tightened = PassportVerifierPolicy {
        min_receipt_count: Some(1),
        ..PassportVerifierPolicy::default()
    };
    service.upsert(&signed_policy(tightened.clone())?).await?;
    let response = service.verify(&holder, &challenge).await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let denied = response.json::<PassportPresentationVerification>().await?;
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

#[tokio::test]
async fn a_registry_corrupted_after_startup_refuses_challenges_and_verifications() -> TestResult {
    let initial = registry_with(signed_policy(PassportVerifierPolicy::default())?)?;
    let service = RunningService::start(Some(&initial)).await?;
    let holder = Holder::new()?;
    let challenge = service.challenge().await?;

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

    let response = service.create_challenge().await?;
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    assert_eq!(
        error_body(response).await?,
        serde_json::json!({"error": expected})
    );

    let response = service.verify(&holder, &challenge).await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        error_body(response).await?,
        serde_json::json!({"error": expected})
    );
    Ok(())
}
