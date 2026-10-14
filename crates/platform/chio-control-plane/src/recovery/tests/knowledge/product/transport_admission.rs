//! Maintenance refuses invalid input before its bounded native worker capacity.
use super::*;
use axum::{body::to_bytes, http::StatusCode};

#[tokio::test]
async fn maintenance_transport_refuses_invalid_input_before_occupied_native_capacity() -> TestResult
{
    let f = KnowledgeFixture::new()?;
    let service = Arc::new(maintenance(&f)?);
    for route in [
        "/v1/recovery/reports/submit",
        "/v1/recovery/reports/read",
        "/v1/recovery/policy/propose",
    ] {
        let response = crate::recovery::maintenance::call_with_occupied_maintenance_capacity(
            service.clone(),
            route,
            b"{".to_vec(),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{route}");
        assert_eq!(
            to_bytes(response.into_body(), 1_024).await?.as_ref(),
            b"recovery.invalid_command"
        );
    }
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, 0);
    Ok(())
}

#[tokio::test]
async fn maintenance_transport_refuses_agent_scope_before_occupied_native_capacity() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let service = Arc::new(maintenance(&f)?);
    let input = DecisionReportV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        workflow_id: WorkflowId::new("unobserved-report-workflow")?,
        expected_revision: SafeInteger::new(1)?,
        decision: RecoveryReportedDecision::NeedsReview,
        reporter_text: ProtectedText::new("classified report probe")?,
        desired_outcome: ProtectedText::new("independent operator review")?,
        attachments: BoundedList::new(vec![])?,
    };
    let reference = ArtifactVersionRefV1 {
        scope: f.f.runtime.scope().clone(),
        artifact: ArtifactId::new("unobserved-trajectory")?,
        version: ArtifactRevisionId::new("unobserved-version")?,
        provenance: ProvenanceDigest::from_bytes([11; 32]),
    };
    let benign = PolicyTrajectoryRefV1 {
        artifact: reference.clone(),
        case_id: EvidenceRef::new("benign")?,
    };
    let proposal = PolicyMaintenanceProposalV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        proposal_id: ReviewId::new("unobserved-proposal")?,
        report_id: EvidenceRef::new("unobserved-report")?,
        base_deployment: DeploymentDigest::from_bytes([12; 32]),
        base_policy: PolicyDigest::from_bytes([13; 32]),
        target_policy: PolicyDigest::from_bytes([14; 32]),
        rationale: ProtectedText::new("classified proposal probe")?,
        affected_contracts: NonEmptyBoundedList::new(vec![SemanticPackageDigest::from_bytes(
            [15; 32],
        )])?,
        benign_trajectories: NonEmptyBoundedList::new(vec![benign])?,
        adversarial_trajectories: NonEmptyBoundedList::new(vec![PolicyTrajectoryRefV1 {
            artifact: reference,
            case_id: EvidenceRef::new("adversarial")?,
        }])?,
        expected_effects: ProtectedText::new("independent review only")?,
        rollback_policy: PolicyDigest::from_bytes([13; 32]),
        rollback_plan: ProtectedText::new("new review for any application")?,
    };
    for (route, body) in [
        (
            "/v1/recovery/reports/submit",
            serde_json::json!({"capability":text::<32768,_>(&f.f.seed.capability)?,"command_id":"unobserved-command","report":text::<32768,_>(&input)?}),
        ),
        (
            "/v1/recovery/reports/read",
            serde_json::json!({"capability":text::<32768,_>(&f.f.seed.capability)?,"report_id":"unobserved-report"}),
        ),
        (
            "/v1/recovery/policy/propose",
            serde_json::json!({"capability":text::<32768,_>(&f.f.seed.capability)?,"proposal":text::<32768,_>(&proposal)?}),
        ),
    ] {
        let response = crate::recovery::maintenance::call_with_occupied_maintenance_capacity(
            service.clone(),
            route,
            chio_core_types::canonical_json_bytes(&body)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{route}");
        assert_eq!(
            to_bytes(response.into_body(), 1_024).await?.as_ref(),
            b"recovery.authority_denied"
        );
    }
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, 0);
    Ok(())
}
