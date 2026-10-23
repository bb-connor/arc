use super::*;
use crate::recovery::vector_test_fixture::{authority_fixture, seed_request, TestResult};
use chio_core_types::{canonical_json_bytes, Keypair};
use serde_json::{json, Value};

fn action() -> TestResult<ActionIntentV1> {
    Ok(serde_json::from_value(
        authority_fixture()?["action"].clone(),
    )?)
}

fn primitive(name: &str) -> TestResult<Value> {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../../tests/bindings/fixtures/protocol-primitives-v1.json"
    ))?;
    Ok(corpus["cases"]
        .as_array()
        .ok_or("primitive cases missing")?
        .iter()
        .find(|case| case["name"] == name)
        .ok_or("primitive fixture missing")?["instance"]
        .clone())
}

#[test]
fn projection_covers_every_request_field_and_redacts_debug() -> TestResult {
    let mut request = seed_request()?;
    request.arguments = json!({"private": "review-payload-canary"});
    let before = canonical_json_bytes(&request)?;
    let projection = request.recovery_review_projection();
    assert_eq!(
        format!("{projection:?}"),
        "RecoveryRequestProjection([redacted])"
    );
    let wire = serde_json::to_value(&projection)?;
    assert_eq!(
        wire["semantics"]["capability_signing_body"],
        serde_json::to_value(request.capability.signing_body())?
    );
    let original = serde_json::to_value(&request)?;
    let classes = [
        ("request_id", "semantics"),
        ("capability", "fixed_authorization"),
        ("tool_name", "semantics"),
        ("server_id", "semantics"),
        ("agent_id", "semantics"),
        ("arguments", "semantics"),
        ("dpop_proof", "fixed_authorization"),
        ("governed_intent", "semantics"),
        ("approval_token", "fixed_authorization"),
        ("approval_tokens", "fixed_authorization"),
        ("threshold_approval_proposal", "fixed_authorization"),
        ("supplemental_authorization", "fixed_authorization"),
        ("model_metadata", "semantics"),
        ("federated_origin_kernel_id", "semantics"),
        ("declassification_grant", "fixed_authorization"),
    ];
    for (field, class) in classes {
        let absent = if field == "approval_tokens" {
            json!([])
        } else {
            Value::Null
        };
        let actual = wire[class].get(field).ok_or("projected field missing")?;
        assert_eq!(actual, original.get(field).unwrap_or(&absent), "{field}");
    }
    assert_eq!(
        wire["native_nonce_claim"],
        serde_json::to_value(&request.execution_nonce)?
    );
    assert_eq!(before, canonical_json_bytes(&request)?);
    Ok(())
}

#[test]
fn every_semantic_field_changes_review_bytes() -> TestResult {
    let request = seed_request()?;
    let action = action()?;
    let semantics = request.recovery_review_projection().canonical_semantics()?;
    let digest = recovery_review_digest(&action, &request)?;
    let wire = serde_json::to_value(&request)?;
    let changes = [
        ("request_id", json!("different-request")),
        ("agent_id", json!("different-agent")),
        ("server_id", json!("different-server")),
        ("tool_name", json!("different-tool")),
        ("arguments", json!({"different": true})),
        ("federated_origin_kernel_id", json!("different-origin")),
        ("model_metadata", json!({"model_id": "different-model"})),
        (
            "governed_intent",
            json!({
                "id": "different-intent", "server_id": "different-server",
                "tool_name": "different-tool", "purpose": "different-purpose"
            }),
        ),
    ];
    for (field, value) in changes {
        let mut changed_wire = wire.clone();
        changed_wire[field] = value;
        let changed: ToolCallRequest = serde_json::from_value(changed_wire)?;
        assert_ne!(
            semantics,
            changed.recovery_review_projection().canonical_semantics()?,
            "{field}"
        );
        assert_ne!(
            digest,
            recovery_review_digest(&action, &changed)?,
            "{field}"
        );
    }
    let mut changed = request.clone();
    changed.capability.id.push_str("-different");
    assert_ne!(
        semantics,
        changed.recovery_review_projection().canonical_semantics()?
    );
    assert_ne!(digest, recovery_review_digest(&action, &changed)?);
    Ok(())
}

fn authorization_variants(
    request: &ToolCallRequest,
) -> TestResult<Vec<(ToolCallRequest, &'static str)>> {
    let signer = Keypair::from_seed(&[61; 32]);
    let mut approval = primitive("governed-approval-token")?;
    approval["approver"] = serde_json::to_value(signer.public_key())?;
    approval["subject"] = serde_json::to_value(signer.public_key())?;
    let mut proposal = primitive("threshold-proposal")?;
    proposal["subject"] = serde_json::to_value(signer.public_key())?;
    proposal["policy_authority"] = serde_json::to_value(signer.public_key())?;
    let mut variants = Vec::new();
    let mut changed = request.clone();
    changed.capability.signature = crate::wrapper_refusals::unrelated_signature(&signer);
    variants.push((changed, "capability"));
    let mut changed = request.clone();
    changed.dpop_proof = Some(DpopProof::sign(
        crate::dpop::DpopProofBody {
            schema: crate::dpop::DPOP_SCHEMA.into(),
            replay_authority: crate::dpop::test_authority(),
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action_hash: "1".repeat(64),
            nonce: "presented-proof".into(),
            issued_at: 100,
            agent_key: signer.public_key(),
        },
        &signer,
    )?);
    variants.push((changed, "dpop_proof"));
    let mut changed = request.clone();
    changed.approval_token = Some(serde_json::from_value(approval.clone())?);
    variants.push((changed, "approval_token"));
    let mut changed = request.clone();
    changed.approval_tokens = vec![serde_json::from_value(approval)?];
    variants.push((changed, "approval_tokens"));
    let mut changed = request.clone();
    changed.threshold_approval_proposal = Some(serde_json::from_value(proposal)?);
    variants.push((changed, "threshold_approval_proposal"));
    let mut changed = request.clone();
    changed.supplemental_authorization = Some(OpaqueSupplementalAuthorization {
        signed_extension: "presented-extension".into(),
    });
    variants.push((changed, "supplemental_authorization"));
    let mut changed = request.clone();
    let body = serde_json::from_value(json!({
        "domain_version": 1, "grant_id": "review-grant", "capability_id": request.capability.id,
        "tenant_id": "review-tenant", "subject_id": "review-subject", "agent_id": "review-agent",
        "session_id": "review-session", "source_label_hash": vec![1; 32],
        "target_label": {"kind": "known", "owners": {}, "compartments": []},
        "destination_id": "tools", "tool_name": "append", "purpose": "review-binding",
        "request_hash": vec![2; 32], "issued_at_unix_seconds": 100, "expires_at_unix_seconds": 200,
        "authority_key_id": "review-authority"
    }))?;
    changed.declassification_grant = Some(SignedDeclassificationGrant::sign(body, &signer)?);
    variants.push((changed, "declassification_grant"));
    Ok(variants)
}

#[test]
fn every_presented_authorization_is_retained_without_changing_semantic_review() -> TestResult {
    let request = seed_request()?;
    let action = action()?;
    let projection = request.recovery_review_projection();
    let semantics = projection.canonical_semantics()?;
    let preview = projection.canonical_action_preview(&action)?;
    let custody = canonical_json_bytes(&projection)?;
    for (changed, field) in authorization_variants(&request)? {
        let reviewed = changed.recovery_review_projection();
        assert_eq!(semantics, reviewed.canonical_semantics()?, "{field}");
        assert_eq!(
            preview,
            reviewed.canonical_action_preview(&action)?,
            "{field}"
        );
        assert_eq!(
            serde_json::to_value(&reviewed)?["fixed_authorization"][field],
            serde_json::to_value(&changed)?[field],
            "{field}"
        );
        assert_ne!(custody, canonical_json_bytes(&reviewed)?, "{field}");
    }
    Ok(())
}

#[test]
fn presented_nonce_is_retained_without_becoming_semantic_authority() -> TestResult {
    let request = seed_request()?;
    let action = action()?;
    let mut changed = request.clone();
    changed.execution_nonce = Some(serde_json::from_value(primitive("execution-nonce")?)?);
    let projection = request.recovery_review_projection();
    let reviewed = changed.recovery_review_projection();
    assert_eq!(
        projection.canonical_semantics()?,
        reviewed.canonical_semantics()?
    );
    assert_eq!(
        recovery_review_digest(&action, &request)?,
        recovery_review_digest(&action, &changed)?
    );
    assert_eq!(
        serde_json::to_value(&reviewed)?["native_nonce_claim"],
        serde_json::to_value(&changed.execution_nonce)?
    );
    assert_ne!(
        canonical_json_bytes(&projection)?,
        canonical_json_bytes(&reviewed)?
    );
    Ok(())
}

#[test]
fn action_preview_binds_the_complete_action_and_semantic_projection() -> TestResult {
    let request = seed_request()?;
    let action = action()?;
    let projection = request.recovery_review_projection();
    let semantics: Value = serde_json::from_slice(projection.canonical_semantics()?.as_bytes())?;
    let preview = projection.canonical_action_preview(&action)?;
    assert_eq!(
        preview.as_bytes(),
        canonical_json_bytes(&(action.clone(), semantics))?
    );
    assert_eq!(
        recovery_review_digest(&action, &request)?.as_bytes(),
        RecoveryDigestDomain::Preview.digest(&preview).as_bytes()
    );
    let mut changed = serde_json::to_value(&action)?;
    changed["workflow_id"] = json!("workflow:different");
    let changed: ActionIntentV1 = serde_json::from_value(changed)?;
    assert_ne!(preview, projection.canonical_action_preview(&changed)?);
    assert_ne!(
        recovery_review_digest(&action, &request)?,
        recovery_review_digest(&changed, &request)?
    );
    Ok(())
}

#[test]
fn typed_integer_semantics_remain_exact() -> TestResult {
    let mut request = seed_request()?;
    request.arguments = json!({"integer": u64::MAX});
    let projection = request.recovery_review_projection();
    let semantics = projection.canonical_semantics()?;
    let decoded: Value = serde_json::from_slice(semantics.as_bytes())?;
    assert_eq!(decoded["arguments"]["integer"].as_u64(), Some(u64::MAX));
    assert_eq!(
        semantics.as_bytes(),
        canonical_json_bytes(&serde_json::to_value(&projection)?["semantics"])?
    );
    let action = action()?;
    let preview = projection.canonical_action_preview(&action)?;
    assert_eq!(
        preview.as_bytes(),
        canonical_json_bytes(&(action.clone(), decoded))?
    );
    assert_eq!(
        recovery_review_digest(&action, &request)?.as_bytes(),
        RecoveryDigestDomain::Preview.digest(&preview).as_bytes()
    );
    let mut adjacent = request.clone();
    adjacent.arguments = json!({"integer": u64::MAX - 1});
    assert_ne!(
        semantics,
        adjacent
            .recovery_review_projection()
            .canonical_semantics()?
    );
    assert_ne!(
        recovery_review_digest(&action, &request)?,
        recovery_review_digest(&action, &adjacent)?
    );
    Ok(())
}
