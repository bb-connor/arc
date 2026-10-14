use super::*;
use crate::admission_operation::{
    AdmissionIdentifier, AdmissionOperationBindingInputV1, AdmissionOperationError,
    AdmissionOperationKind, AdmissionParticipantRequirements, AdmissionRequestBindingV1,
    AuthenticatedRequestNamespace, SideEffectClass,
};
use chio_core::capability::scope::{ChioScope, Operation};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core::Keypair;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture() -> TestResult<(RetainedToolAdmissionRequestV1, AdmissionOperationBindingV1)> {
    let key = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "retained-capability".into(),
            issuer: key.public_key(),
            subject: key.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "server".into(),
                    tool_name: "tool".into(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 1,
            expires_at: 300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &key,
    )?;
    let request: ToolCallRequest = serde_json::from_value(serde_json::json!({
        "request_id": "retained-request", "capability": capability,
        "server_id": "server", "tool_name": "tool", "agent_id": key.public_key().to_hex(),
        "arguments": {"private_argument": "withheld"},
    }))?;
    let matching = [MatchingGrant {
        index: 0,
        grant: &request.capability.scope.grants[0],
        specificity: (0, 0, 0),
    }];
    let profile = AdmissionAuthorityProfileV1::unconfigured_for_test()?;
    let signer =
        FrozenReceiptSigningIdentityV1::new(key.public_key(), ReceiptCryptoFloor::AllowClassical)?;
    let retained = RetainedToolAdmissionRequestV1::from_admission(
        &request,
        &matching,
        &[],
        None,
        &profile,
        &signer,
        None,
    )?;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(AdmissionIdentifier::try_new(
            "authority",
            "retained-authority",
        )?)?,
        request_id: AdmissionIdentifier::try_new("request", request.request_id.clone())?,
        capability_id: AdmissionIdentifier::try_new("capability", request.capability.id.clone())?,
        authorization_capability_hash: AdmissionDigest::try_new(
            "capability",
            sha256_hex(&canonical_json_bytes(&request.capability)?),
        )?,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            immutable_tool_request_hash(&request, &matching, &[], None, &profile, &signer, None)?,
            AdmissionDigest::try_new(
                "action",
                sha256_hex(&canonical_json_bytes(&request.arguments)?),
            )?,
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )?,
        policy_hash: AdmissionDigest::try_new("policy", "a".repeat(64))?,
        effect_class: SideEffectClass::ReadOnly,
    })?;
    retained.validate_binding(&binding)?;
    Ok((retained, binding))
}

#[test]
fn retained_request_requires_explicit_profile_and_signer() -> TestResult {
    let (retained, _) = fixture()?;
    let wire: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    for field in ["authority_profile", "frozen_receipt_signing_identity"] {
        let mut missing = wire.clone();
        missing
            .as_object_mut()
            .ok_or("retained object")?
            .remove(field);
        let error =
            RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&missing)?)
                .err()
                .ok_or("missing authority accepted")?;
        assert!(
            matches!(&error,
            AdmissionOperationStoreError::Operation(AdmissionOperationError::UntrustedInput(cause))
            if cause.code() == "urn:chio:error:attest:signed-json-invalid-shape"),
            "{field}: {error}"
        );
    }
    Ok(())
}

#[test]
fn retained_request_rejects_malformed_signer_shape() -> TestResult {
    let (retained, _) = fixture()?;
    let original: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    for mutation in 0..2 {
        let mut wire = original.clone();
        if mutation == 0 {
            wire["frozen_receipt_signing_identity"] = serde_json::Value::Null;
        } else {
            wire["frozen_receipt_signing_identity"]["unexpected_authority"] = true.into();
        }
        let error =
            RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&wire)?)
                .err()
                .ok_or("malformed signer accepted")?;
        assert!(
            matches!(&error,
            AdmissionOperationStoreError::Operation(AdmissionOperationError::UntrustedInput(cause))
            if cause.code() == "urn:chio:error:attest:signed-json-invalid-shape"),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn retained_request_rejects_signer_substitution() -> TestResult {
    let (retained, binding) = fixture()?;
    let original: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    for mutation in 0..2 {
        let mut wire = original.clone();
        if mutation == 0 {
            wire["frozen_receipt_signing_identity"]["public_key"] =
                serde_json::to_value(Keypair::generate().public_key())?;
        } else {
            wire["frozen_receipt_signing_identity"]["crypto_floor"] = "allow_hybrid".into();
        }
        let changed =
            RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&wire)?)?;
        assert_eq!(
            changed.validate_binding(&binding),
            Err(AdmissionOperationStoreError::Invariant(
                "retained request does not match its admission binding".into(),
            ))
        );
    }
    Ok(())
}

#[test]
fn retained_request_rejects_signer_below_its_floor() -> TestResult {
    let (retained, _) = fixture()?;
    let mut wire: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
    wire["frozen_receipt_signing_identity"]["crypto_floor"] = "pq_required".into();
    let error = RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&wire)?)
        .err()
        .ok_or("insufficient signer accepted")?;
    assert_eq!(
        error,
        AdmissionOperationStoreError::Invariant(
            "retained request receipt signing identity is invalid".into(),
        )
    );
    Ok(())
}

#[test]
fn retained_request_rejects_oversized_material() -> TestResult {
    let error = RetainedToolAdmissionRequestV1::from_canonical_bytes(&vec![b' '; MAX_BYTES + 1])
        .err()
        .ok_or("oversized request accepted")?;
    assert_eq!(
        error,
        AdmissionOperationStoreError::Invariant(
            "retained request exceeds its artifact bound".into(),
        )
    );
    let (retained, _) = fixture()?;
    let mut request = retained.request_for_revalidation().clone();
    request.arguments = serde_json::json!({"oversized": "x".repeat(MAX_BYTES)});
    let error = RetainedToolAdmissionRequestV1::from_admission(
        &request,
        &retained.matching_grants()?,
        &[],
        None,
        retained.authority_profile(),
        retained.frozen_receipt_signing_identity(),
        None,
    )
    .err()
    .ok_or("oversized request retained")?;
    assert_eq!(
        error,
        AdmissionOperationStoreError::Invariant(
            "retained request exceeds its artifact bound".into(),
        )
    );
    Ok(())
}

#[test]
fn immutable_request_commits_to_the_complete_authority_selection() -> TestResult {
    let (retained, binding) = fixture()?;
    let request = retained.request_for_revalidation();
    let independent = serde_json::json!({
        "schema": "chio.tool-admission-request.v1",
        "server_id": request.server_id, "tool_name": request.tool_name,
        "agent_id": request.agent_id, "arguments": request.arguments,
        "governed_intent": request.governed_intent, "model_metadata": request.model_metadata,
        "federated_origin_kernel_id": request.federated_origin_kernel_id,
        "matching_grants": [{"index": 0, "grant": &request.capability.scope.grants[0]}],
        "post_return_steps": [], "security_binding": null,
        "authority_profile": retained.authority_profile(),
        "frozen_receipt_signing_identity": retained.frozen_receipt_signing_identity(),
    });
    assert_eq!(
        binding.immutable_request_hash().as_str(),
        sha256_hex(&canonical_json_bytes(&independent)?)
    );
    Ok(())
}
