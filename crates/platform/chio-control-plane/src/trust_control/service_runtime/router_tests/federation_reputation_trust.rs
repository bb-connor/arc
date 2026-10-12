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
const NOW: u64 = 1_800_000_000;

struct Fixture {
    _directory: tempfile::TempDir,
    state: TrustServiceState,
    old_local: Keypair,
    admitted: Keypair,
}

impl Fixture {
    fn recovered() -> Result<Self, Box<dyn std::error::Error>> {
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
            issued_at: NOW,
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
        let mut registry = FederationAdmissionPolicyRegistry::default();
        registry.upsert(FederationAdmissionPolicyRecord {
            schema: crate::federation_policy::FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA.to_string(),
            published_at: NOW,
            policy: SignedFederatedOpenAdmissionPolicy::sign(artifact, &self.admitted)?,
            anti_sybil: Default::default(),
            minimum_reputation_score,
            note: None,
        })?;
        registry.save(
            self.state
                .config
                .federation_policies_file
                .as_deref()
                .ok_or("policy path")?,
        )?;
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
                    max_invocations: Some(10),
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
                timestamp: NOW,
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
            NOW,
        )
    }
}

#[test]
fn federation_reputation_accepts_the_recovered_authority_receipts() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW);
    let fixture = Fixture::recovered()?;
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
    let _clock = chio_test_support::clock::scope_unix_secs(NOW);
    let fixture = Fixture::recovered()?;
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
    let _clock = chio_test_support::clock::scope_unix_secs(NOW);
    let mut fixture = Fixture::recovered()?;
    fixture.policy(Some(0.0))?;
    fixture.state.config.authority_db_path = None;
    assert!(fixture
        .evaluate(Keypair::generate().public_key().to_hex())
        .is_err());
    Ok(())
}

#[test]
fn federation_without_reputation_keeps_authority_optional() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW);
    let mut fixture = Fixture::recovered()?;
    fixture.policy(None)?;
    fixture.state.config.authority_db_path = None;
    assert!(
        fixture
            .evaluate(Keypair::generate().public_key().to_hex())?
            .accepted
    );
    Ok(())
}
