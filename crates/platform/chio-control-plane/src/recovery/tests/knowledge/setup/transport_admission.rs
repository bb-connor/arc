//! Setup refuses malformed and unprivileged input before scarce native work.
use super::*;
use axum::{body::to_bytes, http::StatusCode};

#[tokio::test]
async fn setup_transport_refuses_invalid_input_before_occupied_native_capacity() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let service = Arc::new(setup(&f, &workflow)?);
    for route in ["/v1/recovery/setup/probe", "/v1/recovery/setup/qualify"] {
        let response = crate::recovery::setup::call_with_occupied_setup_capacity(
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
    assert_eq!(f.f.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[tokio::test]
async fn setup_transport_refuses_agent_scope_before_occupied_native_capacity() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let service = Arc::new(setup(&f, &workflow)?);
    let actor = f.actor(RecoveryPermission::Inspect)?;
    let prepared =
        f.f.authority
            .admission_operation_store()
            .setup_preparation(&actor, &f.f.authority.mutation_fence(), now_ms()?)?;
    let probe = SignedRecoverySetupProbeV1::sign(prepared.probe, &Keypair::from_seed(&[211; 32]))?;
    for (route, body) in [
        (
            "/v1/recovery/setup/probe",
            serde_json::json!({"capability":text::<32768,_>(&f.f.seed.capability)?,"workflow_id":workflow}),
        ),
        (
            "/v1/recovery/setup/qualify",
            serde_json::json!({"capability":text::<32768,_>(&f.f.seed.capability)?,"probe":text::<32768,_>(&probe)?}),
        ),
    ] {
        let response = crate::recovery::setup::call_with_occupied_setup_capacity(
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
    assert_eq!(f.f.process.process("root")?.tree_calls, 2);
    Ok(())
}
