//! A distinct authenticated namespace cannot replace or poison process custody.
use super::*;
use chio_core::session::{
    OAuthBearerFederatedClaims, OAuthBearerSessionAuthInput, SessionAuthContext,
};
use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionReceiptMetadataV1};
use chio_kernel::{SecurityInvocationContext, SecurityInvocationContextV1};
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};

async fn collide_in_authenticated_namespace(
    fixture: &RecoveryFixture,
    request_id: &str,
) -> TestResult<AdmissionOperationId> {
    let key = Keypair::from_seed(&[192; 32]);
    let capability = fixture.kernel.issue_capability(
        &key.public_key(),
        fixture.seed.capability.scope.clone(),
        600,
    )?;
    let session = fixture
        .kernel
        .open_session(key.public_key().to_hex(), vec![capability.clone()])?;
    fixture.kernel.set_session_auth_context(
        &session,
        SessionAuthContext::streamable_http_oauth_bearer_with_claims(OAuthBearerSessionAuthInput {
            principal: Some("authenticated-foreign-operator".into()),
            issuer: Some("https://namespace.example".into()),
            subject: Some("foreign-operator".into()),
            audience: Some("chio-native-test".into()),
            scopes: vec!["tools.invoke".into()],
            federated_claims: OAuthBearerFederatedClaims {
                tenant_id: Some("foreign-request-namespace".into()),
                ..Default::default()
            },
            enterprise_identity: None,
            token_fingerprint: Some("public-synthetic-fingerprint".into()),
            origin: Some("https://namespace.example".into()),
        }),
    )?;
    fixture.kernel.activate_session(&session)?;
    let mut request = fixture.seed.clone();
    request.request_id = request_id.into();
    request.agent_id = key.public_key().to_hex();
    request.capability = capability;
    request.arguments =
        serde_json::json!({"title":"foreign ticket", "body":"foreign private data"});
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("foreign-request-namespace")?,
        SessionId::new(session.as_str())?,
        PrincipalId::new(&request.agent_id)?,
        IsolationEpochId::new("foreign-native-epoch")?,
        LineageId::new(&request.capability.id)?,
        1,
    ));
    let response = fixture
        .kernel
        .evaluate_authenticated_original_for_test(&request, &session, &context)
        .await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        response.receipt.tenant_id.as_deref(),
        Some("foreign-request-namespace")
    );
    // A pre-dispatch signed response can omit projected operation metadata.
    // Resolve only this real authenticated tenant, then verify physical native
    // custody and its terminal projection instead of assuming the public shape.
    let connection = rusqlite::Connection::open(fixture.path.join("admission.db"))?;
    let mut query = connection.prepare(
        "SELECT operation_id FROM admission_operations WHERE request_id=?1
         AND json_extract(CAST(operation_json AS TEXT),'$.binding.authenticated_tenant_id')=?2 LIMIT 2",
    )?;
    let located = query
        .query_map([request_id, "foreign-request-namespace"], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        located.len(),
        1,
        "foreign namespace did not retain exactly one native operation: {:?}",
        response.reason
    );
    let operation_id = AdmissionOperationId::from_persisted(located[0].clone())?;
    let (operation, retained) = fixture
        .authority
        .admission_operation_store()
        .load_retained_tool_request(
            &operation_id,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("foreign native original custody absent")?;
    if let Some(metadata) = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("admission_operation"))
    {
        let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(metadata.clone())?;
        assert_eq!(metadata.operation_id, operation_id);
    }
    assert_eq!(operation.binding().request_id().as_str(), request_id);
    assert_eq!(
        operation
            .binding()
            .to_persisted()
            .authenticated_tenant_id
            .as_str(),
        "foreign-request-namespace"
    );
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    retained.validate_request_material(&request)?;
    retained.validate_native_security_context(&context)?;
    retained.validate_native_security_authority(
        &fixture
            .kernel
            .recovery_deployment(fixture.runtime.scope())?
            .native_authority,
    )?;
    // The real cleanup path records an incident before separately signing its
    // public Deny. The fenced loader above verifies the native commit, terminal
    // projection manifest, canonical records and original recovery lease.
    let Some(chio_kernel::admission_operation::AdmissionTerminalReplay::Incident {
        incident_id,
        ..
    }) = operation.terminal_replay()
    else {
        return Err("foreign native cleanup did not retain its original incident".into());
    };
    let incident_bytes: Vec<u8> = connection.query_row(
        "SELECT record_json FROM admission_operation_terminal_records
         WHERE operation_id=?1 AND record_kind='incident' AND record_id=?2",
        [operation_id.as_str(), incident_id.as_str()],
        |row| row.get(0),
    )?;
    let incident: serde_json::Value = serde_json::from_slice(&incident_bytes)?;
    assert_eq!(chio_core::canonical_json_bytes(&incident)?, incident_bytes);
    assert_eq!(
        incident.get("record_id"),
        Some(&serde_json::to_value(incident_id)?)
    );
    let binding: chio_kernel::admission_operation::AdmissionExactProjectionBindingV1 =
        serde_json::from_value(incident["binding"].clone())?;
    assert_eq!(binding.operation_id(), &operation_id);
    assert_eq!(binding.request_id(), operation.binding().request_id());
    assert_eq!(
        binding.request_binding_hash(),
        operation.binding().request_binding_hash()
    );
    assert_eq!(
        binding.source_operation_version().checked_add(1),
        Some(operation.version())
    );
    assert_eq!(binding.projected_operation_version(), operation.version());
    assert_eq!(binding.store_fence(), &fixture.authority.mutation_fence());
    assert_eq!(
        incident["binding"]["projected_state"],
        serde_json::to_value(AdmissionOperationState::CompensatedBeforeDispatch)?
    );
    assert!(incident["binding"]["retained_dispatch_commit"].is_null());
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(operation_id)
}

fn original_collision_count(fixture: &RecoveryFixture, request: &str) -> TestResult<(i64, i64)> {
    Ok(rusqlite::Connection::open(fixture.path.join("admission.db"))?.query_row(
        "SELECT count(*),count(DISTINCT request_namespace_digest) FROM admission_operations WHERE request_id=?1",
        [request],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

#[tokio::test]
async fn foreign_authenticated_request_id_cannot_poison_original_creation() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let seed = fixture.denied_seed_named("namespace-original").await?;
    let original = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &seed.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("original retained request")?
        .0;
    let foreign = collide_in_authenticated_namespace(&fixture, &seed.request_id).await?;
    assert_ne!(foreign, *original.binding().operation_id());
    assert_eq!(
        original_collision_count(&fixture, &seed.request_id)?,
        (2, 2)
    );
    chio_kernel::recovery::RecoveryProcessOriginPort::verify_original_request(
        &fixture.process,
        fixture.runtime.scope(),
        &seed,
        fixture.process.runtime_id(),
    )?;
    let result = fixture
        .execute(
            "namespace-create",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("namespace-owner")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )
        .await?;
    let record = fixture.record(&result.status.workflow_id)?;
    assert_eq!(
        record
            .origin
            .as_ref()
            .ok_or("original owner")?
            .operation
            .operation_id()
            .as_str(),
        original.binding().operation_id().as_str()
    );
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn foreign_authenticated_request_id_cannot_kill_owned_original_at_capture() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = fixture
        .ready_named("owned-namespace-original", "owned-namespace")
        .await?;
    let record = fixture.record(&workflow)?;
    let origin = record.origin.as_ref().ok_or("original owner")?.clone();
    collide_in_authenticated_namespace(&fixture, origin.request_id.as_str()).await?;
    assert_eq!(
        original_collision_count(&fixture, origin.request_id.as_str())?,
        (2, 2)
    );
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    let result = fixture
        .execute(
            "owned-namespace-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: record.revision,
            },
        )
        .await?;
    assert!(result.original_response.is_some());
    assert!(matches!(
        result.status.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert_eq!(fixture.record(&workflow)?.origin.as_ref(), Some(&origin));
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}
