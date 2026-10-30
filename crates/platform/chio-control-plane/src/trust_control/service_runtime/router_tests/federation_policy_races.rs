//! Federation policy upsert and delete each load the policies file, change it
//! and write it back. One that starts while another sits between its read and
//! its write must be refused, so no committed change is lost.

use super::*;
use crate::federation_policy::{
    FederationAdmissionPolicyRecord, FederationAdmissionPolicyRegistry,
    FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA,
};
use chio_core::crypto::Keypair;
use chio_core::federation::artifacts::{FederationArtifactKind, FederationArtifactReference};
use chio_core::federation::open_admission::{
    FederatedOpenAdmissionPolicyArtifact, SignedFederatedOpenAdmissionPolicy,
    CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA,
};
use chio_core::listing::GenericTrustAdmissionClass;

fn policy(policy_id: &str) -> Result<FederationAdmissionPolicyRecord, Box<dyn std::error::Error>> {
    let reference = |kind, artifact_id: &str| FederationArtifactReference {
        kind,
        schema: "chio.example.v1".to_string(),
        artifact_id: artifact_id.to_string(),
        operator_id: "operator".to_string(),
        sha256: "ab".repeat(32),
        uri: None,
    };
    let artifact = FederatedOpenAdmissionPolicyArtifact {
        schema: CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA.to_string(),
        policy_id: policy_id.to_string(),
        issued_at: 1_700_000_000,
        namespace: "chio://federation/open".to_string(),
        governing_operator_id: "operator".to_string(),
        allowed_admission_classes: vec![GenericTrustAdmissionClass::PublicUntrusted],
        stake_requirements: Vec::new(),
        governing_charter_ref: reference(FederationArtifactKind::GovernanceCharter, "charter"),
        fee_schedule_ref: reference(FederationArtifactKind::OpenMarketFeeSchedule, "fees"),
        explicit_local_review_required: true,
        visibility_only_without_activation: true,
        note: None,
    };
    Ok(FederationAdmissionPolicyRecord {
        schema: FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA.to_string(),
        published_at: 1_700_000_100,
        policy: SignedFederatedOpenAdmissionPolicy::sign(artifact, &Keypair::generate())?,
        anti_sybil: Default::default(),
        minimum_reputation_score: None,
        note: None,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn a_policy_upsert_during_another_is_busy_and_neither_change_is_lost() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("federation-policies.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&FederationAdmissionPolicyRegistry::default())?,
    )?;
    let mut state = metrics_state("service-secret");
    state.config.federation_policies_file = Some(path.clone());
    let (alpha, beta) = (policy("alpha")?, policy("beta")?);
    let (pause, mut opened) =
        crate::signed_input::read_pause::ReadPause::install(&path, HANG_GUARD)?;
    let first = tokio::task::spawn_blocking({
        let state = state.clone();
        let runtime = tokio::runtime::Handle::current();
        move || {
            runtime.block_on(handle_upsert_federation_policy(
                State(state),
                AxumPath("alpha".to_string()),
                bearer("service-secret").test_unwrap(),
                Json(alpha),
            ))
        }
    });
    tokio::time::timeout(HANG_GUARD, opened.recv())
        .await?
        .ok_or("registry read did not enter pause")?;
    let during = handle_upsert_federation_policy(
        State(state.clone()),
        AxumPath("beta".to_string()),
        bearer("service-secret")?,
        Json(beta.clone()),
    )
    .await;
    let (status, text) = status_and_text(during).await?;
    pause.release();
    let response = tokio::time::timeout(HANG_GUARD, first).await??;
    assert_eq!(response.status(), StatusCode::OK);
    if status == StatusCode::OK {
        assert!(
            FederationAdmissionPolicyRegistry::load(&path)?
                .policies
                .contains_key("beta"),
            "a concurrent federation policy upsert lost a committed change"
        );
    }
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{text}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text)?,
        serde_json::json!({"error": CliError::from(RegistryUpdateError::Busy).to_string()})
    );
    assert!(!FederationAdmissionPolicyRegistry::load(&path)?
        .policies
        .contains_key("beta"));

    let retried = handle_upsert_federation_policy(
        State(state),
        AxumPath("beta".to_string()),
        bearer("service-secret")?,
        Json(beta),
    )
    .await;
    assert_eq!(retried.status(), StatusCode::OK);
    let reopened = FederationAdmissionPolicyRegistry::load(&path)?;
    assert!(reopened.policies.contains_key("alpha"));
    assert!(reopened.policies.contains_key("beta"));
    Ok(())
}
