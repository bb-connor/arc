//! The generated root-authority bindings against the schema examples.
//!
//! Every valid example decodes through the generated type. The generated
//! types enforce unknown-member rejection, closed enums, required members,
//! string patterns and string lengths, but not `const`, `maximum`, `minItems`,
//! `maxItems` or the `if`/`then`/`else`, `not` and conditional `oneOf` rules.
//! The invalid examples that the generated types accept are pinned below:
//! each is a schema-only rejection that the hand-written decoder of the type
//! must enforce.
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(
    clippy::clone_on_copy,
    clippy::derivable_impls,
    clippy::enum_variant_names,
    clippy::large_enum_variant,
    clippy::unwrap_used,
    dead_code,
    non_snake_case
)]
#[rustfmt::skip]
#[path = "../src/_generated/chio_wire_v1.rs"]
mod generated;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

const SCHEMA_ONLY_REJECTIONS: &[&str] = &[
    "delegation-context.entra-claim-on-id-jag.json",
    "delegation-context.id-jag-without-identity-digest.json",
    "delegation-context.id-jag-without-kid.json",
    "delegation-context.id-jag-without-provider-record.json",
    "delegation-context.introspection-with-artifact-digest.json",
    "delegation-context.local-as-with-artifact-digest.json",
    "delegation-context.oidc-jwt-without-kid.json",
    "delegation-context.operator-key-with-artifact-digest.json",
    "delegation-context.retained-on-static-bearer.json",
    "delegation-context.static-bearer-claims.json",
    "delegation-context.static-bearer-issuer.json",
    "delegation-context.static-bearer-with-kid.json",
    "delegation-context.static-bearer-with-provider-record.json",
    "delegation-context.subject-tenant-salt-ref.json",
    "enterprise-provider-identity.both-key-sources.json",
    "enterprise-provider-identity.introspection-with-jwks-url.json",
    "enterprise-provider-identity.no-key-source.json",
    "idp-key-snapshot.ec-with-ed25519-curve.json",
    "idp-key-snapshot.ec-without-y.json",
    "idp-key-snapshot.okp-with-p256-curve.json",
    "idp-key-snapshot.rsa-without-modulus.json",
    "presentation.too-many-ancestors.json",
    "revocation-admin-request.unknown-kind.json",
    "root-policy.clock-skew-61.json",
    "root-policy.disclosure-default-inline.json",
    "root-policy.entra-claim-on-id-jag.json",
    "root-policy.entra-max-assertion-lifetime.json",
    "root-policy.id-jag-without-allowed-algs.json",
    "root-policy.id-jag-without-identity-digest.json",
    "root-policy.id-jag-without-provider-record.json",
    "root-policy.introspection-with-allowed-algs.json",
    "root-policy.local-as-with-allowed-algs.json",
    "root-policy.principal-on-entra.json",
    "root-policy.retain-artifact-on-entra.json",
    "root-policy.static-bearer-with-provider-record.json",
    "root-policy.static-bearer-without-principal.json",
    "root-policy.too-many-exchange-keys.json",
    "verifier-trust.empty-kernel-keys.json",
];

fn decode<T: DeserializeOwned>(text: &str) -> Result<(), String> {
    serde_json::from_str::<T>(text)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn decode_example(path: &Path) -> Result<(), String> {
    use generated::*;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("example file name");
    let text = std::fs::read_to_string(path).expect("example bytes");
    match name.split('.').next().expect("example stem") {
        "root-anchor" => decode::<root_authority_root_anchor::ChioRootAnchor>(&text),
        "delegation-context" => decode::<capability_presentation::ChioDelegationContext>(&text),
        "root-policy" => decode::<root_authority_root_policy::ChioRootPolicy>(&text),
        "enterprise-provider-identity" => decode::<
            root_authority_enterprise_provider_identity::ChioEnterpriseProviderIdentity,
        >(&text),
        "idp-key-snapshot" => decode::<root_authority_idp_key_snapshot::ChioIdPKeySnapshot>(&text),
        "verifier-trust" => decode::<root_authority_verifier_trust::ChioVerifierTrust>(&text),
        "revocation-request" => {
            decode::<root_authority_revocation_request::ChioRevocationRequest>(&text)
        }
        "revocation-entry" => decode::<root_authority_revocation_entry::ChioRevocationEntry>(&text),
        "revocation-admin-request" => {
            decode::<root_authority_revocation_admin_request::ChioRevocationAdminRequest>(&text)
        }
        "presentation" => decode::<capability_presentation::ChioCapabilityPresentation>(&text),
        "disclosure" => decode::<receipt_disclosure::ChioReceiptDisclosure>(&text),
        "settlement-closure" => decode::<receipt_settlement_closure::ChioSettlementClosure>(&text),
        other => panic!("no generated type for example stem {other}"),
    }
}

fn examples(kind: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1/root_authority/examples")
        .join(kind);
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("examples directory")
        .map(|entry| entry.expect("examples entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no examples under {}", dir.display());
    paths
}

#[test]
fn generated_bindings_decode_every_valid_example() {
    for path in examples("valid") {
        if let Err(error) = decode_example(&path) {
            panic!("{} does not decode: {error}", path.display());
        }
    }
}

#[test]
fn generated_bindings_accept_exactly_the_pinned_schema_only_rejections() {
    let accepted: BTreeSet<String> = examples("invalid")
        .iter()
        .filter(|path| decode_example(path).is_ok())
        .map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .expect("example file name")
                .to_owned()
        })
        .collect();
    let pinned: BTreeSet<String> = SCHEMA_ONLY_REJECTIONS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    assert_eq!(
        accepted, pinned,
        "generated bindings must accept exactly SCHEMA_ONLY_REJECTIONS"
    );
}

/// Signed valid examples: example stem, JSON pointer of the signed object,
/// member holding its signer key, and the wrapper id that signs it.
const PLACEHOLDER_SIGNED_EXAMPLES: &[(&str, &str, &str, &str)] = &[
    ("root-policy", "", "policy_key", "chio.root-policy.v1"),
    (
        "idp-key-snapshot",
        "",
        "exchange_key",
        "chio.idp-key-snapshot.v1",
    ),
    (
        "revocation-request",
        "",
        "revoker_key",
        "chio.revocation-request.v1",
    ),
    (
        "settlement-closure",
        "",
        "kernel_key",
        "chio.settlement-closure.v1",
    ),
    ("presentation", "/leaf", "issuer", "chio.capability.v1"),
];

/// The examples carry placeholder signatures. A verifier holding the signer
/// key the example names refuses each one under its wrapper id.
#[test]
fn placeholder_example_signatures_are_refused() {
    let mut refused = 0;
    for path in examples("valid") {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("example file name");
        let stem = name.split('.').next().expect("example stem");
        let Some((_, pointer, signer, schema_id)) = PLACEHOLDER_SIGNED_EXAMPLES
            .iter()
            .find(|(candidate, ..)| *candidate == stem)
        else {
            continue;
        };
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("example bytes"))
                .expect("example parses");
        let mut signed = document
            .pointer(pointer)
            .expect("signed object")
            .as_object()
            .expect("signed object is an object")
            .clone();
        let signature = signed
            .remove("signature")
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("{name} carries a signature"));
        let key = chio_core_types::PublicKey::from_hex(
            signed[*signer].as_str().expect("signer key member"),
        )
        .expect("signer key decodes");
        let signature =
            chio_core_types::Signature::from_hex(&signature).expect("signature decodes");
        assert!(
            chio_core_types::verify_wrapped(&key, schema_id, &signed, &signature).is_err(),
            "{name} placeholder signature verifies under {schema_id}"
        );
        refused += 1;
    }
    assert_eq!(refused, 7);
}
