//! Federation policy signatures and the export scope they bound.

use chio_bundle_verify::federation::{
    ensure_query_within_federation_policy, verify_federation_policy,
};
use chio_core_types::canonical::CanonicalBytes;
use chio_core_types::crypto::{ExemptFormat, Keypair};
use chio_core_types::receipt::evidence::{
    EvidenceExportQuery, FederationPolicyBody, FederationPolicyDocument, ReceiptReadBoundary,
    FEDERATION_POLICY_SCHEMA,
};
use chio_test_support::prelude::*;

fn tenant(tenant: &str) -> EvidenceExportQuery {
    EvidenceExportQuery {
        tenant: Some(tenant.to_string()),
        read_boundary: Some(ReceiptReadBoundary::tenant_scoped(tenant)),
        ..EvidenceExportQuery::default()
    }
}

#[test]
fn ensure_query_within_federation_policy_rejects_tenant_scope_expansion() {
    let error = ensure_query_within_federation_policy(&tenant("tenant-a"), &tenant("tenant-b"))
        .test_unwrap_err();
    assert!(error.message().contains("tenant scope"), "{error}");
}

#[test]
fn ensure_query_within_federation_policy_rejects_admin_all_under_tenant_scope() {
    let error = ensure_query_within_federation_policy(
        &tenant("tenant-a"),
        &EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..EvidenceExportQuery::default()
        },
    )
    .test_unwrap_err();
    assert!(error.message().contains("admin-all"), "{error}");
}

#[test]
fn ensure_query_within_federation_policy_allows_admin_policy_tenant_narrowing() {
    ensure_query_within_federation_policy(
        &EvidenceExportQuery::admin_all(),
        &EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..EvidenceExportQuery::default()
        },
    )
    .test_unwrap();
}

fn signed_policy(query: EvidenceExportQuery) -> FederationPolicyDocument {
    let keypair = Keypair::generate();
    let body = FederationPolicyBody {
        schema: FEDERATION_POLICY_SCHEMA.to_string(),
        issuer: "issuer-a".to_string(),
        partner: "partner-b".to_string(),
        signer_public_key: keypair.public_key(),
        created_at: 10,
        expires_at: 20,
        query,
        require_proofs: false,
        purpose: None,
    };
    let signature = keypair
        .sign_wrapped(
            FEDERATION_POLICY_SCHEMA,
            &CanonicalBytes::from_serializable(&body).test_unwrap(),
        )
        .test_unwrap();
    FederationPolicyDocument { body, signature }
}

#[test]
fn signed_federation_policy_rejects_unbound_read_boundary() {
    let error =
        verify_federation_policy(&signed_policy(EvidenceExportQuery::default())).test_unwrap_err();
    assert!(error.message().contains("read boundary"), "{error}");
}

#[test]
fn federation_policy_signature_covers_its_scope() {
    let mut policy = signed_policy(tenant("tenant-a"));
    verify_federation_policy(&policy).test_unwrap();
    policy.body.query = tenant("tenant-b");
    let error = verify_federation_policy(&policy).test_unwrap_err();
    assert!(error.message().contains("signature"), "{error}");
}

#[test]
fn federation_policy_refuses_an_unwrapped_signature() {
    let mut policy = signed_policy(tenant("tenant-a"));
    let signer = Keypair::generate();
    policy.body.signer_public_key = signer.public_key();
    let canonical = CanonicalBytes::from_serializable(&policy.body).test_unwrap();
    policy.signature = signer.sign_exempt(ExemptFormat::JwsSigningInput, canonical.as_bytes());
    let error = verify_federation_policy(&policy).test_unwrap_err();
    assert!(error.message().contains("signature"), "{error}");
}
