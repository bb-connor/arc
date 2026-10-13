//! Source-bound live qualification fixture. No model or credential enters Rust policy.
use super::*;
mod fixture;
mod host;
use fixture::prepare_case;

#[tokio::test]
async fn comparative_artifact_restart_preserves_exact_read_authority() -> TestResult {
    let fixture = prepare_case("artifact", "lost_ack_restart").await?;
    assert!(Box::pin(fixture.execute()).await.is_ok());
    let facts = fixture.facts()?;
    assert_eq!(facts["artifact_releases"], 1);
    assert_eq!(facts["artifact_deliveries"], 2);
    assert_eq!(facts["recovery_success"], true);
    assert_eq!(facts["duplicate_effects"], 0);
    Ok(())
}

#[tokio::test]
async fn comparative_native_fixture_has_two_useful_workflows_and_fresh_refusals() -> TestResult {
    for workflow in ["support", "artifact"] {
        for case in [
            "authorized",
            "lost_ack_restart",
            "wrong_authority",
            "conflicting_basis",
        ] {
            let fixture = prepare_case(workflow, case).await?;
            let result = Box::pin(fixture.execute()).await;
            let facts = fixture.facts()?;
            let positive = matches!(case, "authorized" | "lost_ack_restart");
            assert_eq!(result.is_ok(), positive, "{workflow}/{case}");
            assert_eq!(facts["useful_completion"], positive);
            assert_eq!(facts["unauthorized_effects"], 0);
            assert_eq!(facts["duplicate_effects"], 0);
            assert_eq!(facts["source_label_retained"], true, "{workflow}/{case}");
        }
    }
    Ok(())
}
