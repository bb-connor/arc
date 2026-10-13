use super::*;
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::{sha256_hex, Keypair};
use chio_kernel::admission_operation::{
    AdmissionAuthorityProfileV1, AdmissionAuthoritySelectionV1, AdmissionBeginResult,
    AdmissionOperationStoreError, RetainedToolAdmissionRequestV1,
};
use serde_json::json;

fn original(
    fixture: &Fixture,
    request_id: &str,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    let key = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("capability-{request_id}"),
            issuer: key.public_key(),
            subject: key.public_key(),
            scope: serde_json::from_value(json!({"grants": [{
                "server_id": "server", "tool_name": "tool", "operations": ["invoke"],
            }]}))?,
            issued_at: AUTHORITY_TIME / 1_000,
            expires_at: AUTHORITY_TIME / 1_000 + 300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &key,
    )?;
    let request: chio_kernel::ToolCallRequest = serde_json::from_value(json!({
        "request_id": request_id, "capability": capability,
        "server_id": "server", "tool_name": "tool", "agent_id": key.public_key().to_hex(),
        "arguments": {"private_argument": "retained-rpc-request"},
    }))?;
    let profile = AdmissionAuthorityProfileV1::new(AdmissionAuthoritySelectionV1 {
        runtime_hook_installed: false,
        swarm_admission_required: false,
        runtime_enforces_swarm_authority: false,
        runtime_requires_dispatch_revalidation: false,
        runtime: None,
        approval: None,
        dpop: None,
    })?;
    let signer = json!({"public_key": key.public_key(), "crypto_floor": "allow_classical"});
    let immutable = json!({
        "schema": "chio.tool-admission-request.v1",
        "server_id": request.server_id, "tool_name": request.tool_name,
        "agent_id": request.agent_id, "arguments": request.arguments,
        "governed_intent": request.governed_intent, "model_metadata": request.model_metadata,
        "federated_origin_kernel_id": request.federated_origin_kernel_id,
        "matching_grants": [{"index": 0, "grant": request.capability.scope.grants[0]}],
        "post_return_steps": [], "security_binding": null,
        "authority_profile": profile, "frozen_receipt_signing_identity": signer,
    });
    let retained =
        RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&json!({
            "schema": "chio.retained-tool-admission-request.v1", "request": request,
            "matching_grant_indices": [0], "post_return_steps": [],
            "authority_profile": profile, "frozen_receipt_signing_identity": signer,
        }))?)?;
    let digest = |field, value: &[u8]| AdmissionDigest::try_new(field, sha256_hex(value));
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(AdmissionIdentifier::try_new(
            "coordinator_authority_id",
            fixture.fence().store_uuid,
        )?)?,
        request_id: AdmissionIdentifier::try_new("request_id", request_id)?,
        capability_id: AdmissionIdentifier::try_new("capability_id", &request.capability.id)?,
        authorization_capability_hash: digest(
            "authorization_capability_hash",
            &canonical_json_bytes(&request.capability)?,
        )?,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            digest("immutable_request_hash", &canonical_json_bytes(&immutable)?)?,
            digest(
                "action_parameter_hash",
                &canonical_json_bytes(&request.arguments)?,
            )?,
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )?,
        policy_hash: AdmissionDigest::try_new("policy_hash", "a".repeat(64))?,
        effect_class: SideEffectClass::SideEffecting,
    })?;
    retained.validate_binding(&binding)?;
    Ok((
        AdmissionOperationV1::prepare(binding, fixture.fence().owner_epoch)?,
        retained,
    ))
}

#[test]
fn remote_retained_begin_round_trip_preserves_original_bytes() -> TestResult {
    let fixture = Fixture::new()?;
    let (operation, original) = original(&fixture, "remote-retained-begin")?;
    let result = fixture.remote.operations.begin_with_retained_tool_request(
        &operation,
        &original,
        &fixture.fence(),
        AUTHORITY_TIME,
    )?;
    assert_eq!(result, AdmissionBeginResult::Created(operation.clone()));
    let head = fixture.head()?;
    let (loaded, retained) = fixture
        .remote
        .operations
        .load_retained_tool_request(
            operation.binding().operation_id(),
            &fixture.fence(),
            AUTHORITY_TIME,
        )?
        .ok_or("remote original request missing")?;
    assert_eq!(loaded, operation);
    assert_eq!(retained.canonical_bytes(), original.canonical_bytes());
    assert_eq!(
        fixture.remote.operations.begin_with_retained_tool_request(
            &operation,
            &original,
            &fixture.fence(),
            AUTHORITY_TIME,
        )?,
        AdmissionBeginResult::ExactReplay {
            operation,
            terminal_replay: None
        }
    );
    assert_eq!(fixture.head()?, head);
    Ok(())
}

#[test]
fn remote_retained_read_preserves_atomic_local_original() -> TestResult {
    let fixture = Fixture::new()?;
    let (operation, original) = original(&fixture, "remote-retained-read")?;
    fixture.operations().begin_with_retained_tool_request(
        &operation,
        &original,
        &fixture.fence(),
        AUTHORITY_TIME,
    )?;
    let head = fixture.head()?;
    let (loaded, retained) = fixture
        .remote
        .operations
        .load_retained_tool_request(
            operation.binding().operation_id(),
            &fixture.fence(),
            AUTHORITY_TIME,
        )?
        .ok_or("remote original request missing")?;
    assert_eq!(loaded, operation);
    assert_eq!(retained.canonical_bytes(), original.canonical_bytes());
    assert_eq!(fixture.head()?, head);
    Ok(())
}

#[test]
fn remote_begin_wire_requires_original_request() -> TestResult {
    let fixture = Fixture::new()?;
    let (operation, _) = original(&fixture, "remote-missing-original")?;
    let head = fixture.head()?;
    let response = fixture.wire_call(&AdmissionAuthorityRequest::new(
        Some(fixture.fence()),
        AdmissionAuthorityAction::Begin,
        &json!({"operation": operation.to_persisted(), "fence": fixture.fence(),
            "trusted_now_unix_ms": AUTHORITY_TIME}),
    )?)?;
    let error = response.error.ok_or("missing original request accepted")?;
    assert_eq!(error.code, AdmissionAuthorityErrorCode::InvalidRequest);
    assert_eq!(error.message, "missing field `retained_request`");
    assert_eq!(fixture.head()?, head);
    assert_eq!(
        fixture
            .operations()
            .load_by_operation_id(operation.binding().operation_id())?,
        None
    );
    Ok(())
}

#[test]
fn remote_unretained_begin_refuses_without_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let (operation, _) = original(&fixture, "remote-unretained")?;
    let head = fixture.head()?;
    assert_eq!(
        fixture
            .remote
            .operations
            .begin(&operation, &fixture.fence(), AUTHORITY_TIME),
        Err(AdmissionOperationStoreError::Invariant(
            "remote admission requires original tool request material".into(),
        )),
    );
    assert_eq!(fixture.head()?, head);
    Ok(())
}

#[test]
fn remote_retained_ports_refuse_stale_fence() -> TestResult {
    let fixture = Fixture::new()?;
    let (operation, original) = original(&fixture, "remote-stale-owner")?;
    let head = fixture.head()?;
    let mut stale = fixture.fence();
    stale.owner_epoch += 1;
    assert_eq!(
        fixture.remote.operations.begin_with_retained_tool_request(
            &operation,
            &original,
            &stale,
            AUTHORITY_TIME,
        ),
        Err(AdmissionOperationStoreError::Fenced),
    );
    let read_error = fixture
        .remote
        .operations
        .load_retained_tool_request(operation.binding().operation_id(), &stale, AUTHORITY_TIME)
        .err()
        .ok_or("stale original request read accepted")?;
    assert_eq!(read_error, AdmissionOperationStoreError::Fenced);
    assert_eq!(fixture.head()?, head);
    Ok(())
}
