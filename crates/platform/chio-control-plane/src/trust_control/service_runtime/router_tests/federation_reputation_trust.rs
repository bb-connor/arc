use super::*;
use crate::trust_control::service_runtime::issuance::evaluate_federation_policy_request;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::federation::artifacts::{FederationArtifactKind, FederationArtifactReference};
use chio_core::federation::open_admission::{
    FederatedOpenAdmissionPolicyArtifact, SignedFederatedOpenAdmissionPolicy,
    CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA,
};
use chio_core::listing::GenericTrustAdmissionClass;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::metadata::ReceiptAttributionMetadata;
use chio_kernel::{CapabilityAuthority, LocalCapabilityAuthority, ReceiptStore};
use chio_store_sqlite::{SqliteCapabilityAuthority, SqliteReceiptStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const POLICY_ID: &str = "reputation-trust";

struct Fixture {
    _directory: tempfile::TempDir,
    state: TrustServiceState,
    now: u64,
    old_local: Keypair,
    admitted: Keypair,
}

impl Fixture {
    fn recovered(now: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let mut state = metrics_state("service-secret");
        state.finding_challenge_clock = chio_test_support::clock::clock();
        let authority_path = directory.path().join("authority.sqlite3");
        state.config.authority_db_path = Some(authority_path.clone());
        state.config.federation_policies_file = Some(directory.path().join("policies.json"));
        let authority = SqliteCapabilityAuthority::open_with_clock(
            &authority_path,
            Arc::clone(&state.finding_challenge_clock),
        )?;
        let old_local = authority.local_keypair()?;
        let recovery_root = Keypair::from_seed(&[97; 32]);
        let anchor = authority.initialize_replication_with_recovery(
            "federation-reputation",
            Some(&recovery_root.public_key()),
        )?;
        let recovered = SqliteCapabilityAuthority::open_with_clock(
            directory.path().join("recovered.sqlite3"),
            Arc::clone(&state.finding_challenge_clock),
        )?;
        recovered.pin_replication_anchor(&anchor)?;
        recovered.apply_signed_snapshot(&authority.signed_snapshot()?)?;
        recovered.recover_authority(&recovery_root)?;
        let admitted = recovered.local_keypair()?;
        authority.apply_signed_snapshot(&recovered.signed_snapshot()?)?;
        assert_ne!(old_local.public_key(), admitted.public_key());
        let status = report_validation::load_authority_status_for_state(&state)
            .map_err(|response| format!("authority fixture refused: {}", response.status()))?;
        assert_eq!(
            status.trusted_public_keys,
            vec![admitted.public_key().to_hex()]
        );
        state.receipt_store = Some(Arc::new(SqliteReceiptStore::open_with_clock(
            directory.path().join("receipts.sqlite3"),
            Arc::clone(&state.finding_challenge_clock),
        )?));
        let fixture = Self {
            _directory: directory,
            state,
            now,
            old_local,
            admitted,
        };
        fixture.policy(Some(0.01))?;
        Ok(fixture)
    }

    fn policy(&self, minimum_reputation_score: Option<f64>) -> TestResult {
        let reference = |kind, id: &str| FederationArtifactReference {
            kind,
            schema: "chio.example.v1".to_string(),
            artifact_id: id.to_string(),
            operator_id: "operator".to_string(),
            sha256: "ab".repeat(32),
            uri: None,
        };
        let artifact = FederatedOpenAdmissionPolicyArtifact {
            schema: CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA.to_string(),
            policy_id: POLICY_ID.to_string(),
            issued_at: self.now,
            namespace: "chio://federation/reputation".to_string(),
            governing_operator_id: "operator".to_string(),
            allowed_admission_classes: vec![GenericTrustAdmissionClass::PublicUntrusted],
            stake_requirements: Vec::new(),
            governing_charter_ref: reference(FederationArtifactKind::GovernanceCharter, "charter"),
            fee_schedule_ref: reference(FederationArtifactKind::OpenMarketFeeSchedule, "fees"),
            explicit_local_review_required: true,
            visibility_only_without_activation: true,
            note: None,
        };
        let record = FederationAdmissionPolicyRecord {
            schema: crate::federation_policy::FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA.to_string(),
            published_at: self.now,
            policy: SignedFederatedOpenAdmissionPolicy::sign(artifact, &self.admitted)?,
            anti_sybil: Default::default(),
            minimum_reputation_score,
            note: None,
        };
        let path = self
            .state
            .config
            .federation_policies_file
            .as_deref()
            .ok_or("policy path")?;
        FederationAdmissionPolicyRegistry::update(path, |registry| registry.upsert(record))?;
        Ok(())
    }

    fn history(&self, signer: &Keypair) -> Result<String, Box<dyn std::error::Error>> {
        let subject = Keypair::generate().public_key();
        let authority = LocalCapabilityAuthority::new_with_clock(
            signer.clone(),
            Arc::clone(&self.state.finding_challenge_clock),
        );
        let capability = authority.issue_capability(
            &subject,
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Read],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..Default::default()
            },
            300,
        )?;
        let store = self.state.receipt_store.as_deref().ok_or("receipt store")?;
        store.record_capability_snapshot(&capability, None)?;
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: format!("receipt-{}", capability.id),
                timestamp: self.now,
                capability_id: capability.id.clone(),
                tool_server: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                action: ToolCallAction::from_parameters(serde_json::json!({"path":"/safe/file"}))?,
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "ab".repeat(32),
                policy_hash: "cd".repeat(32),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject.to_hex(), issuer_key: signer.public_key().to_hex(),
                        delegation_depth: 0, grant_index: Some(0),
                    }
                })),
                trust_level: Default::default(),
                tenant_id: None,
                kernel_key: signer.public_key(),
                bbs_projection_version: None,
            },
            signer,
        )?;
        store.append_chio_receipt(&receipt)?;
        let inspection = crate::issuance::inspect_local_reputation_with_store(
            &subject.to_hex(),
            store,
            None,
            None,
            None,
            None,
            &[signer.public_key().to_hex()],
            &chio_kernel::ReceiptReadContext::admin_service(),
        )?;
        assert_eq!(inspection.scorecard.history_depth.receipt_count, 1);
        assert!(inspection.effective_score > 0.01);
        Ok(subject.to_hex())
    }

    fn evaluate(
        &self,
        subject_key: String,
    ) -> Result<FederationAdmissionEvaluationResponse, CliError> {
        evaluate_federation_policy_request(
            &self.state,
            &FederationAdmissionEvaluationRequest {
                policy_id: POLICY_ID.to_string(),
                subject_key,
                requested_admission_class: GenericTrustAdmissionClass::PublicUntrusted,
                proof_of_work_nonce: None,
            },
            self.now,
        )
    }
}

#[test]
fn federation_reputation_accepts_the_recovered_authority_receipts() -> TestResult {
    let now = now_unix_secs()?;
    let _clock = chio_test_support::clock::scope_unix_secs(now);
    let fixture = Fixture::recovered(now)?;
    let subject = fixture.history(&fixture.admitted)?;
    let response = fixture.evaluate(subject)?;
    assert!(
        response.accepted,
        "admitted authority receipts were excluded: {response:?}"
    );
    Ok(())
}

#[test]
fn federation_reputation_excludes_the_displaced_local_key() -> TestResult {
    let now = now_unix_secs()?;
    let _clock = chio_test_support::clock::scope_unix_secs(now);
    let fixture = Fixture::recovered(now)?;
    let subject = fixture.history(&fixture.old_local)?;
    let response = fixture.evaluate(subject)?;
    assert!(
        !response.accepted,
        "displaced custody contributed reputation: {response:?}"
    );
    Ok(())
}

#[test]
fn federation_reputation_requires_an_admitted_authority_even_at_zero_threshold() -> TestResult {
    let now = now_unix_secs()?;
    let _clock = chio_test_support::clock::scope_unix_secs(now);
    let mut fixture = Fixture::recovered(now)?;
    fixture.policy(Some(0.0))?;
    fixture.state.config.authority_db_path = None;
    let error = fixture
        .evaluate(Keypair::generate().public_key().to_hex())
        .test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("admitted trust-control authority"),
        "unexpected refusal: {error}"
    );
    Ok(())
}

#[test]
fn federation_without_reputation_keeps_authority_optional() -> TestResult {
    let now = now_unix_secs()?;
    let _clock = chio_test_support::clock::scope_unix_secs(now);
    let mut fixture = Fixture::recovered(now)?;
    fixture.policy(None)?;
    fixture.state.config.authority_db_path = None;
    assert!(
        fixture
            .evaluate(Keypair::generate().public_key().to_hex())?
            .accepted
    );
    Ok(())
}

#[test]
fn federation_reputation_preserves_rotation_grace_and_excludes_revoked_keys() -> TestResult {
    let now = now_unix_secs()?;
    let _clock = chio_test_support::clock::scope_unix_secs(now);
    let mut fixture = Fixture::recovered(now)?;
    let authority_path = fixture._directory.path().join("recovered.sqlite3");
    fixture.state.config.authority_db_path = Some(authority_path.clone());
    let subject = fixture.history(&fixture.admitted)?;
    let authority = SqliteCapabilityAuthority::open_with_clock(
        &authority_path,
        Arc::clone(&fixture.state.finding_challenge_clock),
    )?;
    let rotated = authority.rotate_with_verification_deadline(now + 3_600)?;
    assert_ne!(rotated.public_key, fixture.admitted.public_key());
    assert!(rotated
        .trusted_public_keys
        .contains(&fixture.admitted.public_key()));
    let response = fixture.evaluate(subject.clone())?;
    assert!(
        response.accepted,
        "rotation dropped valid history: {response:?}"
    );

    let revoked = authority.revoke_issuer(&fixture.admitted.public_key())?;
    assert!(!revoked
        .trusted_public_keys
        .contains(&fixture.admitted.public_key()));
    let response = fixture.evaluate(subject)?;
    assert!(
        !response.accepted,
        "revoked key still contributed: {response:?}"
    );
    assert_eq!(response.observed_reputation_score, Some(0.0));
    Ok(())
}
