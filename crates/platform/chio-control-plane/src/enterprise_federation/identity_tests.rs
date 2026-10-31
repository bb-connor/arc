#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::{json, Value};

use super::*;

fn record(edit: impl FnOnce(&mut Value)) -> EnterpriseProviderRecord {
    let mut value = json!({
        "provider_id": "acme-okta",
        "kind": "oidc_jwks",
        "enabled": true,
        "provenance": { "configured_from": "file", "trust_material_ref": "okta-org-acme" },
        "trust_boundary": { "allowed_audiences": ["https://chio.example"] },
        "issuer": "https://issuer.example",
        "jwks_url": "https://issuer.example/jwks",
        "subject_mapping": { "principal_source": "sub", "tenant_id_field": "iss" }
    });
    edit(&mut value);
    serde_json::from_value(value).unwrap()
}

#[test]
fn identity_projects_the_record_members() {
    let identity = record(|_| {}).identity().unwrap();
    assert_eq!(identity.provider_id.as_str(), "acme-okta");
    assert_eq!(identity.kind, ProviderRecordKind::OidcJwks);
    assert_eq!(identity.issuer.as_str(), "https://issuer.example");
    assert_eq!(
        identity.jwks_url.as_ref().map(HttpsUrl::as_str),
        Some("https://issuer.example/jwks")
    );
    assert_eq!(identity.audiences.len(), 1);
    assert_eq!(identity.subject_mapping.tenant_id_field.as_str(), "iss");
    assert_eq!(identity.trust_material_ref.as_str(), "okta-org-acme");
}

#[test]
fn identity_ignores_enabled_so_a_disabled_record_keeps_its_digest() {
    let enabled = record(|_| {}).identity().unwrap().digest().unwrap();
    let disabled = record(|value| value["enabled"] = json!(false))
        .identity()
        .unwrap()
        .digest()
        .unwrap();
    assert_eq!(enabled, disabled);
}

#[test]
fn identity_refuses_each_unusable_record() {
    let refused = |edit: fn(&mut Value)| record(edit).identity().unwrap_err();
    assert_eq!(
        refused(|value| value["validation_errors"] = json!(["bad"])),
        ProviderIdentityError::ValidationErrors
    );
    assert_eq!(
        refused(|value| value["kind"] = json!("scim")),
        ProviderIdentityError::KindNotReferenced
    );
    assert_eq!(
        refused(|value| value["kind"] = json!("saml")),
        ProviderIdentityError::KindNotReferenced
    );
    assert_eq!(
        refused(|value| {
            value.as_object_mut().unwrap().remove("issuer");
        }),
        ProviderIdentityError::IssuerMissing
    );
    assert_eq!(
        refused(|value| {
            value["subject_mapping"]
                .as_object_mut()
                .unwrap()
                .remove("tenant_id_field");
        }),
        ProviderIdentityError::TenantIdFieldMissing
    );
    assert_eq!(
        refused(|value| {
            value["provenance"]
                .as_object_mut()
                .unwrap()
                .remove("trust_material_ref");
        }),
        ProviderIdentityError::TrustMaterialRefMissing
    );
    assert!(matches!(
        refused(|value| value["jwks_url"] = json!("http://issuer.example/jwks")),
        ProviderIdentityError::Url {
            field: "jwks_url",
            ..
        }
    ));
}
