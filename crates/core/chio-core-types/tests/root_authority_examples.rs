//! The hand-written root-authority types against the schema examples.
//!
//! Every valid example decodes and re-serializes to the same JSON value.
//! Every invalid example rejects at decode with the pinned reason,
//! including the conditional rules the generated bindings do not enforce.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chio_core_types::capability::anchor::RootAnchor;
use chio_core_types::root_authority::{
    CapabilityPresentation, DelegationContext, EnterpriseProviderIdentity, IdpKeySnapshot,
    RootPolicy,
};
use serde::{de::DeserializeOwned, Serialize};

const REJECTIONS: &[(&str, &str)] = &[
    (
        "delegation-context.anchor-padding.json",
        "unknown field `pad`",
    ),
    (
        "delegation-context.claim-commitment-padding.json",
        "data did not match any variant of untagged enum ClaimValue",
    ),
    (
        "delegation-context.claim-wrong-type.json",
        "data did not match any variant of untagged enum ClaimValue",
    ),
    (
        "delegation-context.claims-padding.json",
        "unknown field `pad`",
    ),
    (
        "delegation-context.entra-claim-on-id-jag.json",
        "`oid` is not allowed for oauth_id_jag",
    ),
    (
        "delegation-context.exchange-padding.json",
        "unknown field `pad`",
    ),
    (
        "delegation-context.id-jag-without-identity-digest.json",
        "`provider_identity_digest` is required for oauth_id_jag",
    ),
    (
        "delegation-context.id-jag-without-kid.json",
        "`kid` is required for oauth_id_jag",
    ),
    (
        "delegation-context.id-jag-without-provider-record.json",
        "`provider_record_id` is required for oauth_id_jag",
    ),
    (
        "delegation-context.introspection-with-artifact-digest.json",
        "`artifact_digest` is not allowed for oauth_introspection",
    ),
    (
        "delegation-context.issuer-nul.json",
        "`uri` is not a URI without NUL or whitespace",
    ),
    (
        "delegation-context.issuer-oversized.json",
        "`uri` has 2070 characters, outside 1..=2048",
    ),
    (
        "delegation-context.local-as-with-artifact-digest.json",
        "`artifact_digest` is not allowed for chio_local_as",
    ),
    (
        "delegation-context.oidc-jwt-without-kid.json",
        "`kid` is required for oidc_jwt",
    ),
    ("delegation-context.padding.json", "unknown field `pad`"),
    (
        "delegation-context.operator-key-with-artifact-digest.json",
        "`artifact_digest` is not allowed for chio_operator_key",
    ),
    (
        "delegation-context.retained-on-static-bearer.json",
        "`artifact_retained` has a value not admitted for operator_static_bearer",
    ),
    (
        "delegation-context.static-bearer-claims.json",
        "`claims` is not allowed for operator_static_bearer",
    ),
    (
        "delegation-context.static-bearer-issuer.json",
        "`issuer` has a value not admitted for operator_static_bearer",
    ),
    (
        "delegation-context.static-bearer-with-kid.json",
        "`kid` is not allowed for operator_static_bearer",
    ),
    (
        "delegation-context.static-bearer-with-provider-record.json",
        "`provider_record_id` is not allowed for operator_static_bearer",
    ),
    (
        "delegation-context.subject-commitment-padding.json",
        "unknown field `pad`",
    ),
    (
        "delegation-context.subject-tenant-salt-ref.json",
        "`subject.salt_ref` must be `anchor.sub`",
    ),
    (
        "delegation-context.tenant-commitment-padding.json",
        "unknown field `pad`",
    ),
    (
        "delegation-context.unknown-claim.json",
        "unknown field `email`",
    ),
    (
        "enterprise-provider-identity.both-key-sources.json",
        "exactly one of `jwks_url, jwks` is required",
    ),
    (
        "enterprise-provider-identity.enabled-member.json",
        "unknown field `enabled`",
    ),
    (
        "enterprise-provider-identity.inline-jwks-padding.json",
        "unknown field `pad`",
    ),
    (
        "enterprise-provider-identity.introspection-with-jwks-url.json",
        "`jwks_url, jwks` is not allowed for oauth_introspection",
    ),
    (
        "enterprise-provider-identity.jwks-url-http.json",
        "`https_url` is not an https:// URL without NUL or whitespace",
    ),
    (
        "enterprise-provider-identity.no-key-source.json",
        "exactly one of `jwks_url, jwks` is required",
    ),
    (
        "enterprise-provider-identity.padding.json",
        "unknown field `pad`",
    ),
    (
        "enterprise-provider-identity.scim-kind.json",
        "unknown variant `scim`",
    ),
    (
        "enterprise-provider-identity.subject-mapping-padding.json",
        "unknown field `pad`",
    ),
    (
        "idp-key-snapshot.ec-with-ed25519-curve.json",
        "`crv` has a value not admitted for EC",
    ),
    (
        "idp-key-snapshot.ec-without-y.json",
        "`y` is required for EC",
    ),
    ("idp-key-snapshot.jwk-padding.json", "unknown field `pad`"),
    (
        "idp-key-snapshot.modulus-oversized.json",
        "`base64url` has 1401 characters, outside 1..=1400",
    ),
    (
        "idp-key-snapshot.okp-with-p256-curve.json",
        "`crv` has a value not admitted for OKP",
    ),
    ("idp-key-snapshot.padding.json", "unknown field `pad`"),
    (
        "idp-key-snapshot.private-jwk-member.json",
        "unknown field `d`",
    ),
    (
        "idp-key-snapshot.rsa-without-modulus.json",
        "`n` is required for RSA",
    ),
    (
        "idp-key-snapshot.source-http.json",
        "`source` is not an https:// JWKS URL or registry:<provider_id>",
    ),
    (
        "idp-key-snapshot.source-unknown-scheme.json",
        "`source` is not an https:// JWKS URL or registry:<provider_id>",
    ),
    ("presentation.missing-leaf.json", "missing field `leaf`"),
    ("presentation.padding.json", "unknown field `pad`"),
    (
        "presentation.too-many-ancestors.json",
        "`ancestors` has 17 items, outside 0..=16",
    ),
    (
        "root-anchor.digest-uppercase-hex.json",
        "`digest` is not sha256:<64 lowercase hex>",
    ),
    ("root-anchor.padding.json", "unknown field `pad`"),
    (
        "root-anchor.unknown-kind.json",
        "unknown variant `self_anchored`",
    ),
    ("root-policy.alg-hs256.json", "unknown variant `HS256`"),
    ("root-policy.alg-none.json", "unknown variant `none`"),
    (
        "root-policy.clock-skew-61.json",
        "`max_clock_skew_secs` is 61, outside 0..=60",
    ),
    (
        "root-policy.disclosure-default-inline.json",
        "unknown variant `inline`",
    ),
    ("root-policy.disclosure-padding.json", "unknown field `pad`"),
    (
        "root-policy.entra-claim-on-id-jag.json",
        "`oid` is not allowed for oauth_id_jag",
    ),
    (
        "root-policy.entra-max-assertion-lifetime.json",
        "`max_assertion_lifetime_secs` is not allowed for entra_jwt",
    ),
    (
        "root-policy.id-jag-without-allowed-algs.json",
        "`match.allowed_algs` is required for oauth_id_jag",
    ),
    (
        "root-policy.id-jag-without-identity-digest.json",
        "`match.provider_identity_digest` is required for oauth_id_jag",
    ),
    (
        "root-policy.id-jag-without-provider-record.json",
        "`match.provider_record_id` is required for oauth_id_jag",
    ),
    (
        "root-policy.identity-digest-uppercase.json",
        "`digest` is not sha256:<64 lowercase hex>",
    ),
    (
        "root-policy.projection-second-slash.json",
        "`idp_scope_projection` is not server/tool with a non-empty server and a non-empty tool without `/`",
    ),
    (
        "root-policy.projection-without-slash.json",
        "`idp_scope_projection` is not server/tool with a non-empty server and a non-empty tool without `/`",
    ),
    (
        "root-policy.inline-field-not-pointer.json",
        "`inline_fields` is not a non-empty RFC 6901 JSON pointer of at most 256 characters",
    ),
    (
        "root-policy.inline-fields-padding.json",
        "unknown field `pad`",
    ),
    (
        "root-policy.introspection-with-allowed-algs.json",
        "`match.allowed_algs` is not allowed for oauth_introspection",
    ),
    (
        "root-policy.local-as-with-allowed-algs.json",
        "`match.allowed_algs` is not allowed for chio_local_as",
    ),
    (
        "root-policy.match-audience-claim.json",
        "unknown field `aud`",
    ),
    ("root-policy.match-issuer.json", "unknown field `issuer`"),
    (
        "root-policy.match-jwks-uri.json",
        "unknown field `jwks_uri`",
    ),
    ("root-policy.match-padding.json", "unknown field `pad`"),
    ("root-policy.padding.json", "unknown field `pad`"),
    (
        "root-policy.principal-on-entra.json",
        "`principal` is not allowed for entra_jwt",
    ),
    (
        "root-policy.retain-artifact-on-entra.json",
        "`retain_idp_artifact` is not allowed for entra_jwt",
    ),
    (
        "root-policy.rule-id-nul.json",
        "`identifier` contains a NUL character",
    ),
    ("root-policy.rule-padding.json", "unknown field `pad`"),
    (
        "root-policy.rule-tenant-claim.json",
        "unknown field `tenant_claim`",
    ),
    (
        "root-policy.signature-oversized-der.json",
        "invalid signature: crypto hex input exceeds its encoded size limit",
    ),
    (
        "root-policy.static-bearer-with-provider-record.json",
        "`match.provider_record_id` is not allowed for operator_static_bearer",
    ),
    (
        "root-policy.static-bearer-without-principal.json",
        "`principal` is required for operator_static_bearer",
    ),
    (
        "root-policy.too-many-exchange-keys.json",
        "`exchange_keys` has 17 items, outside 1..=16",
    ),
    (
        "root-policy.tool-disclosure-padding.json",
        "unknown field `pad`",
    ),
    (
        "root-policy.unknown-match-claim.json",
        "unknown field `email`",
    ),
    (
        "root-policy.unknown-recorded-claim.json",
        "unknown field `email`",
    ),
];

fn round_trip<T: DeserializeOwned + Serialize>(text: &str) -> Result<serde_json::Value, String> {
    let value: T = serde_json::from_str(text).map_err(|error| error.to_string())?;
    Ok(serde_json::to_value(&value).expect("re-serialize"))
}

fn decode_example(name: &str, text: &str) -> Option<Result<serde_json::Value, String>> {
    let decoded = match name.split('.').next().expect("example stem") {
        "root-anchor" => round_trip::<RootAnchor>(text),
        "delegation-context" => round_trip::<DelegationContext>(text),
        "root-policy" => round_trip::<RootPolicy>(text),
        "enterprise-provider-identity" => round_trip::<EnterpriseProviderIdentity>(text),
        "idp-key-snapshot" => round_trip::<IdpKeySnapshot>(text),
        "presentation" => round_trip::<CapabilityPresentation>(text),
        _ => return None,
    };
    Some(decoded)
}

fn examples(kind: &str) -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1/root_authority/examples")
        .join(kind);
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("examples directory")
        .map(|entry| entry.expect("examples entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("example file name")
                .to_owned();
            let text = std::fs::read_to_string(&path).expect("example bytes");
            (name, text)
        })
        .collect()
}

#[test]
fn valid_examples_decode_and_round_trip() {
    let mut decoded = 0;
    for (name, text) in examples("valid") {
        let Some(result) = decode_example(&name, &text) else {
            continue;
        };
        let value = result.unwrap_or_else(|error| panic!("{name} does not decode: {error}"));
        let original: serde_json::Value = serde_json::from_str(&text).expect("example json");
        assert_eq!(value, original, "{name} does not round-trip");
        decoded += 1;
    }
    assert_eq!(decoded, 12);
}

#[test]
fn invalid_examples_reject_with_the_pinned_reason() {
    let mut seen = BTreeSet::new();
    for (name, text) in examples("invalid") {
        let Some(result) = decode_example(&name, &text) else {
            continue;
        };
        let (_, expected) = REJECTIONS
            .iter()
            .find(|(pinned, _)| *pinned == name)
            .unwrap_or_else(|| panic!("{name} has no pinned rejection"));
        let error = result.expect_err(&name);
        assert!(
            error.starts_with(expected),
            "{name}: expected `{expected}`, got `{error}`"
        );
        seen.insert(name);
    }
    let pinned: BTreeSet<String> = REJECTIONS
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    assert_eq!(
        seen, pinned,
        "every pinned rejection names an existing example"
    );
}
