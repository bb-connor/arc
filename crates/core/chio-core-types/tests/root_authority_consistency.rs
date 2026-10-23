//! Root policy load rules, key snapshot signatures and the consistency of an
//! anchored root with its delegation context and the loaded root policy.
//! Every refusal is pinned to its exact error.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::anchor::{AnchorKind, RootAnchor};
use chio_core_types::capability::attenuation::{Attenuation, DelegationLink, DelegationLinkBody};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::root_authority::{
    check_root_consistency, DelegationContext, HolderClass, IdpKeySnapshot,
    IdpKeySnapshotSignatureError, KeySnapshotSource, LoadedRootPolicy, RootAuthorityShapeError,
    RootConsistencyError, RootConsistencyInput, RootPolicy, RootPolicyLoadError, Sha256Digest,
};
use chio_core_types::{canonical_json_bytes, sha256};
use serde_json::{json, Value};

const NOW: u64 = 1_792_234_800;
const ISSUED_AT: u64 = NOW - 5;
const EXPIRES_AT: u64 = NOW + 290;
const RULE_ID: &str = "okta-crm-agents";
const PROVIDER_DIGEST: &str =
    "sha256:eba2bdd1bff4ffd93cdd19b349c62676c3580522201a061d8635d894c36195d1";

fn policy_keypair() -> Keypair {
    Keypair::from_seed(&[1; 32])
}

fn exchange_keypair() -> Keypair {
    Keypair::from_seed(&[2; 32])
}

fn other_keypair() -> Keypair {
    Keypair::from_seed(&[3; 32])
}

fn grant(tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: "crm".into(),
        tool_name: tool.into(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

fn scope_digest(scope: &ChioScope) -> Sha256Digest {
    Sha256Digest::from_hash(sha256(&canonical_json_bytes(scope).unwrap()))
}

fn rule_json() -> Value {
    let ceiling = scope(vec![grant("search"), grant("get"), grant("update")]);
    json!({
        "rule_id": RULE_ID,
        "match": {
            "anchor_kind": "oauth_id_jag",
            "provider_record_id": "acme-okta",
            "provider_identity_digest": PROVIDER_DIGEST,
            "allowed_algs": ["RS256"],
            "claims": { "client_id": ["mcp-client-claude"] }
        },
        "idp_scope_projection": { "crm.read": ["crm/search", "crm/get"] },
        "ceiling_scope": ceiling,
        "ceiling_scope_hash": scope_digest(&ceiling),
        "recorded_claims": { "client_id": "plain" },
        "holder_classes": ["edge_session", "caller"],
        "capability_ttl_secs": 300,
        "max_assertion_lifetime_secs": 300,
        "max_clock_skew_secs": 30
    })
}

fn static_bearer_rule_json(rule_id: &str) -> Value {
    let ceiling = scope(vec![grant("search")]);
    json!({
        "rule_id": rule_id,
        "match": { "anchor_kind": "operator_static_bearer" },
        "ceiling_scope": ceiling,
        "ceiling_scope_hash": scope_digest(&ceiling),
        "recorded_claims": {},
        "holder_classes": ["edge_session"],
        "principal": "dev:alice",
        "tenant_value": "dev"
    })
}

fn policy_json() -> Value {
    json!({
        "schema": "chio.root-policy.v1",
        "policy_id": "rp_acme_prod",
        "policy_key": policy_keypair().public_key(),
        "exchange_keys": [exchange_keypair().public_key()],
        "rules": [rule_json()],
        "disclosure": { "default": "committed" },
        "valid_from": NOW - 1_000,
        "valid_until": NOW + 100_000,
        "signature": "00".repeat(64)
    })
}

fn signed_policy(edit: impl FnOnce(&mut Value)) -> RootPolicy {
    let mut value = policy_json();
    edit(&mut value);
    let unsigned: RootPolicy = serde_json::from_value(value).unwrap();
    resign(unsigned, &policy_keypair())
}

fn resign(policy: RootPolicy, signer: &Keypair) -> RootPolicy {
    let signature = signer.sign_canonical(&policy.signing_body()).unwrap().0;
    let mut fields = policy.into_fields();
    fields.signature = signature;
    RootPolicy::new(fields).unwrap()
}

fn load(policy: RootPolicy) -> Result<LoadedRootPolicy, RootPolicyLoadError> {
    policy.load(&policy_keypair().public_key(), NOW)
}

fn context_json(root_scope: &ChioScope) -> Value {
    json!({
        "schema": "chio.delegation-context.v1",
        "anchor": {
            "kind": "oauth_id_jag",
            "issuer": "https://acme.okta.com",
            "provider_record_id": "acme-okta",
            "provider_identity_digest": PROVIDER_DIGEST,
            "key_snapshot_digest": format!("sha256:{}", "3a".repeat(32)),
            "kid": "k-okta-1",
            "alg": "RS256",
            "artifact_digest": format!("sha256:{}", "cd".repeat(32)),
            "artifact_retained": false,
            "replay_key_digest": format!("sha256:{}", "a7".repeat(32)),
            "token_iat": EXPIRES_AT - 300,
            "token_exp": EXPIRES_AT,
            "subject": { "commit": format!("sha256:{}", "a9".repeat(32)), "salt_ref": "anchor.sub" },
            "tenant": { "commit": format!("sha256:{}", "e9".repeat(32)), "salt_ref": "anchor.tenant" },
            "claims": { "client_id": "mcp-client-claude" }
        },
        "exchange": {
            "exchange_key": exchange_keypair().public_key(),
            "exchanged_at": ISSUED_AT,
            "request_digest": format!("sha256:{}", "17".repeat(32)),
            "holder": "edge_session"
        },
        "root_policy_rule_id": RULE_ID,
        "effective_root_scope_hash": scope_digest(root_scope)
    })
}

struct Fixture {
    policy: LoadedRootPolicy,
    context: DelegationContext,
    root: CapabilityToken,
    anchor: RootAnchor,
    sender_key: Option<PublicKey>,
}

impl Fixture {
    fn new() -> Self {
        Self::with(|_| {}, |_| {}, &exchange_keypair(), vec![grant("search")])
    }

    fn with(
        edit_policy: impl FnOnce(&mut Value),
        edit_context: impl FnOnce(&mut Value),
        signer: &Keypair,
        root_grants: Vec<ToolGrant>,
    ) -> Self {
        let policy = load(signed_policy(edit_policy)).unwrap();
        let root_scope = scope(root_grants);
        let mut context = context_json(&root_scope);
        edit_context(&mut context);
        let context: DelegationContext = serde_json::from_value(context).unwrap();
        let root = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-root".into(),
                issuer: signer.public_key(),
                subject: other_keypair().public_key(),
                scope: root_scope,
                issued_at: ISSUED_AT,
                expires_at: EXPIRES_AT,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            signer,
        )
        .unwrap();
        let anchor = RootAnchor {
            kind: context.anchor.kind,
            context_digest: context.digest().unwrap(),
            root_policy_digest: *policy.digest(),
            anchored_at: context.exchange.exchanged_at,
            assertion_exp: context.anchor.token_exp,
        };
        Self {
            policy,
            context,
            root,
            anchor,
            sender_key: None,
        }
    }

    fn check(&self) -> Result<(), RootConsistencyError> {
        check_root_consistency(RootConsistencyInput {
            root: &self.root,
            anchor: &self.anchor,
            context: &self.context,
            policy: &self.policy,
            sender_key: self.sender_key.as_ref(),
        })
    }
}

fn consistency_error(
    edit_policy: impl FnOnce(&mut Value),
    edit_context: impl FnOnce(&mut Value),
) -> RootConsistencyError {
    Fixture::with(
        edit_policy,
        edit_context,
        &exchange_keypair(),
        vec![grant("search")],
    )
    .check()
    .unwrap_err()
}

#[test]
fn policy_loads_with_its_digest() {
    let policy = signed_policy(|_| {});
    let digest = policy.digest().unwrap();
    let loaded = load(policy).unwrap();
    assert_eq!(loaded.digest(), &digest);
    assert!(loaded.lists_exchange_key(&exchange_keypair().public_key()));
    assert!(!loaded.lists_exchange_key(&other_keypair().public_key()));
    assert_eq!(loaded.check_valid_at(NOW), Ok(()));
}

#[test]
fn policy_load_refuses_an_unpinned_policy_key() {
    let error = signed_policy(|_| {})
        .load(&other_keypair().public_key(), NOW)
        .unwrap_err();
    assert_eq!(error, RootPolicyLoadError::PolicyKeyNotPinned);
}

#[test]
fn policy_load_refuses_a_body_changed_after_signing() {
    let mut fields = signed_policy(|_| {}).into_fields();
    fields.valid_until += 1;
    let policy = RootPolicy::new(fields).unwrap();
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::InvalidSignature
    );
}

#[test]
fn policy_load_refuses_a_signature_by_another_key() {
    let policy = resign(signed_policy(|_| {}), &other_keypair());
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::InvalidSignature
    );
}

#[test]
fn policy_load_refuses_an_empty_validity_window() {
    let policy = signed_policy(|value| value["valid_until"] = json!(NOW - 1_000));
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::EmptyValidityWindow
    );
}

#[test]
fn policy_is_out_of_force_before_valid_from_and_at_valid_until() {
    let early = signed_policy(|value| value["valid_from"] = json!(NOW + 1));
    assert_eq!(
        load(early).unwrap_err(),
        RootPolicyLoadError::NotYetValid {
            valid_from: NOW + 1
        }
    );
    let late = signed_policy(|value| value["valid_until"] = json!(NOW));
    assert_eq!(
        load(late).unwrap_err(),
        RootPolicyLoadError::Expired { valid_until: NOW }
    );
    let loaded = load(signed_policy(|_| {})).unwrap();
    assert_eq!(
        loaded.check_valid_at(NOW + 100_000),
        Err(RootPolicyLoadError::Expired {
            valid_until: NOW + 100_000
        })
    );
}

#[test]
fn policy_load_refuses_inline_disclosure_tools() {
    let policy = signed_policy(|value| {
        value["disclosure"]["tools"] = json!({
            "crm/search": { "parameters": { "inline_fields": ["/query"] }, "result": { "inline_fields": [] } }
        });
    });
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::InlineDisclosureUnsupported
    );
}

#[test]
fn policy_load_refuses_a_repeated_rule_id() {
    let policy = signed_policy(|value| value["rules"] = json!([rule_json(), rule_json()]));
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::DuplicateRuleId {
            rule_id: RULE_ID.into()
        }
    );
}

#[test]
fn policy_load_refuses_a_second_static_bearer_rule() {
    let policy = signed_policy(|value| {
        value["rules"] = json!([
            static_bearer_rule_json("dev-static"),
            static_bearer_rule_json("dev-static-2")
        ]);
    });
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::DuplicateStaticBearerRule
    );
}

#[test]
fn policy_load_refuses_entra_agent_id_rules() {
    let policy = signed_policy(|value| {
        let rule = &mut value["rules"][0];
        rule["match"]["anchor_kind"] = json!("entra_agent_id");
        rule.as_object_mut()
            .unwrap()
            .remove("max_assertion_lifetime_secs");
    });
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::UnsupportedAnchorKind {
            rule_id: RULE_ID.into(),
            kind: AnchorKind::EntraAgentId
        }
    );
}

#[test]
fn policy_load_refuses_identity_provider_artifact_retention() {
    let policy = signed_policy(|value| value["rules"][0]["retain_idp_artifact"] = json!(true));
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::ArtifactRetentionUnsupported {
            rule_id: RULE_ID.into()
        }
    );
}

#[test]
fn policy_load_refuses_a_ceiling_hash_that_does_not_recompute() {
    let policy = signed_policy(|value| {
        value["rules"][0]["ceiling_scope_hash"] = json!(format!("sha256:{}", "00".repeat(32)));
    });
    assert_eq!(
        load(policy).unwrap_err(),
        RootPolicyLoadError::CeilingScopeHashMismatch {
            rule_id: RULE_ID.into()
        }
    );
}

#[test]
fn policy_built_in_code_is_validated_by_new() {
    let mut fields = signed_policy(|_| {}).into_fields();
    fields.exchange_keys = (0..17_u8)
        .map(|seed| Keypair::from_seed(&[seed; 32]).public_key())
        .collect();
    assert_eq!(
        RootPolicy::new(fields).unwrap_err(),
        RootAuthorityShapeError::Items {
            field: "exchange_keys",
            min: 1,
            max: 16,
            actual: 17
        }
    );
}

#[test]
fn root_agrees_with_its_anchor_context_and_policy() {
    assert_eq!(Fixture::new().check(), Ok(()));
}

#[test]
fn caller_root_binds_to_the_presented_sender_key() {
    let mut fixture = Fixture::with(
        |_| {},
        |context| context["exchange"]["holder"] = json!("caller"),
        &exchange_keypair(),
        vec![grant("search")],
    );
    fixture.sender_key = Some(other_keypair().public_key());
    assert_eq!(fixture.check(), Ok(()));
}

#[test]
fn delegated_token_is_not_a_root() {
    let mut fixture = Fixture::new();
    fixture.root.delegation_chain.push(
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "cap-parent".into(),
                delegator: exchange_keypair().public_key(),
                delegatee: other_keypair().public_key(),
                attenuations: Vec::new(),
                timestamp: ISSUED_AT,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            },
            &exchange_keypair(),
        )
        .unwrap(),
    );
    assert_eq!(fixture.check(), Err(RootConsistencyError::NotARoot));
}

#[test]
fn anchor_naming_another_policy_denies() {
    let mut fixture = Fixture::new();
    fixture.anchor.root_policy_digest = Sha256Digest::from_bytes([7; 32]);
    assert_eq!(
        fixture.check(),
        Err(RootConsistencyError::RootPolicyDigestMismatch)
    );
}

#[test]
fn anchor_naming_another_context_denies() {
    let mut fixture = Fixture::new();
    fixture.anchor.context_digest = Sha256Digest::from_bytes([7; 32]);
    assert_eq!(
        fixture.check(),
        Err(RootConsistencyError::ContextDigestMismatch)
    );
}

#[test]
fn anchor_kind_must_equal_the_context_kind() {
    let mut fixture = Fixture::new();
    fixture.anchor.kind = AnchorKind::OidcJwt;
    assert_eq!(
        fixture.check(),
        Err(RootConsistencyError::AnchorKindMismatch)
    );
}

#[test]
fn assertion_exp_must_equal_the_token_exp() {
    let mut fixture = Fixture::new();
    fixture.anchor.assertion_exp += 1;
    assert_eq!(
        fixture.check(),
        Err(RootConsistencyError::AssertionExpMismatch)
    );
}

#[test]
fn anchored_at_must_equal_the_exchange_time() {
    let mut fixture = Fixture::new();
    fixture.anchor.anchored_at += 1;
    assert_eq!(
        fixture.check(),
        Err(RootConsistencyError::AnchoredAtMismatch)
    );
}

#[test]
fn root_expiring_after_the_assertion_denies() {
    let error = consistency_error(
        |_| {},
        |context| context["anchor"]["token_exp"] = json!(EXPIRES_AT - 1),
    );
    assert_eq!(
        error,
        RootConsistencyError::ExpiresAfterAssertion {
            expires_at: EXPIRES_AT,
            assertion_exp: EXPIRES_AT - 1
        }
    );
}

#[test]
fn root_issuer_must_equal_the_context_exchange_key() {
    let error = consistency_error(
        |_| {},
        |context| context["exchange"]["exchange_key"] = json!(other_keypair().public_key()),
    );
    assert_eq!(error, RootConsistencyError::ExchangeKeyMismatch);
}

#[test]
fn root_signed_by_an_unlisted_exchange_key_denies() {
    let error = Fixture::with(
        |_| {},
        |context| context["exchange"]["exchange_key"] = json!(other_keypair().public_key()),
        &other_keypair(),
        vec![grant("search")],
    )
    .check()
    .unwrap_err();
    assert_eq!(error, RootConsistencyError::ExchangeKeyNotListed);
}

#[test]
fn root_scope_must_hash_to_the_effective_root_scope_hash() {
    let error = consistency_error(
        |_| {},
        |context| {
            context["effective_root_scope_hash"] = json!(format!("sha256:{}", "00".repeat(32)));
        },
    );
    assert_eq!(error, RootConsistencyError::ScopeHashMismatch);
}

#[test]
fn context_naming_an_unknown_rule_denies() {
    let error = consistency_error(
        |_| {},
        |context| context["root_policy_rule_id"] = json!("missing-rule"),
    );
    assert_eq!(error, RootConsistencyError::UnknownRule);
}

#[test]
fn rule_kind_must_equal_the_anchor_kind() {
    let error = consistency_error(
        |_| {},
        |context| context["anchor"]["kind"] = json!("oidc_jwt"),
    );
    assert_eq!(error, RootConsistencyError::RuleKindMismatch);
}

#[test]
fn holder_class_outside_the_rule_denies() {
    let error = consistency_error(
        |policy| policy["rules"][0]["holder_classes"] = json!(["caller"]),
        |_| {},
    );
    assert_eq!(
        error,
        RootConsistencyError::HolderClassNotAllowed {
            holder: HolderClass::EdgeSession
        }
    );
}

#[test]
fn caller_root_without_a_sender_key_denies() {
    let error = consistency_error(
        |_| {},
        |context| context["exchange"]["holder"] = json!("caller"),
    );
    assert_eq!(error, RootConsistencyError::SenderKeyMissing);
}

#[test]
fn caller_root_subject_must_be_the_sender_key() {
    let mut fixture = Fixture::with(
        |_| {},
        |context| context["exchange"]["holder"] = json!("caller"),
        &exchange_keypair(),
        vec![grant("search")],
    );
    fixture.sender_key = Some(policy_keypair().public_key());
    assert_eq!(
        fixture.check(),
        Err(RootConsistencyError::SubjectNotSenderKey)
    );
}

#[test]
fn edge_session_root_presented_with_a_sender_key_denies() {
    let mut fixture = Fixture::new();
    fixture.sender_key = Some(other_keypair().public_key());
    assert_eq!(
        fixture.check(),
        Err(RootConsistencyError::SenderKeyOnEdgeSession)
    );
}

#[test]
fn edge_session_root_with_a_proof_required_grant_denies() {
    let mut proof_required = grant("search");
    proof_required.dpop_required = Some(true);
    let error = Fixture::with(|_| {}, |_| {}, &exchange_keypair(), vec![proof_required])
        .check()
        .unwrap_err();
    assert_eq!(error, RootConsistencyError::ProofRequiredGrantOnEdgeSession);
}

#[test]
fn edge_session_under_a_ceiling_with_a_proof_required_grant_denies() {
    let error = Fixture::with(
        |policy| {
            let mut ceiling = scope(vec![grant("search"), grant("get"), grant("update")]);
            ceiling.grants[2].dpop_required = Some(true);
            policy["rules"][0]["ceiling_scope"] = serde_json::to_value(&ceiling).unwrap();
            policy["rules"][0]["ceiling_scope_hash"] =
                serde_json::to_value(scope_digest(&ceiling)).unwrap();
        },
        |_| {},
        &exchange_keypair(),
        vec![grant("search")],
    )
    .check()
    .unwrap_err();
    assert_eq!(error, RootConsistencyError::ProofRequiredGrantOnEdgeSession);
}

#[test]
fn context_provider_record_must_equal_the_rule() {
    let error = consistency_error(
        |_| {},
        |context| {
            context["anchor"]["provider_identity_digest"] =
                json!(format!("sha256:{}", "00".repeat(32)));
        },
    );
    assert_eq!(error, RootConsistencyError::ProviderMismatch);
}

#[test]
fn root_scope_beyond_the_ceiling_denies() {
    let error = Fixture::with(
        |_| {},
        |_| {},
        &exchange_keypair(),
        vec![grant("search"), grant("delete")],
    )
    .check()
    .unwrap_err();
    assert_eq!(error, RootConsistencyError::ScopeExceedsCeiling);
}

#[test]
fn root_lifetime_beyond_the_rule_ttl_denies() {
    let error = consistency_error(
        |policy| policy["rules"][0]["capability_ttl_secs"] = json!(60),
        |_| {},
    );
    assert_eq!(
        error,
        RootConsistencyError::LifetimeExceedsRule {
            lifetime: EXPIRES_AT - ISSUED_AT,
            capability_ttl: 60
        }
    );
}

#[test]
fn assertion_lifetime_beyond_the_rule_bound_denies() {
    let error = consistency_error(
        |policy| policy["rules"][0]["max_assertion_lifetime_secs"] = json!(100),
        |_| {},
    );
    assert_eq!(
        error,
        RootConsistencyError::AssertionLifetimeExceedsRule {
            lifetime: 300,
            max: 100
        }
    );
}

#[test]
fn recorded_claims_must_match_the_rule_modes() {
    let unlisted = consistency_error(
        |_| {},
        |context| context["anchor"]["claims"]["scope"] = json!(["crm.read"]),
    );
    assert_eq!(
        unlisted,
        RootConsistencyError::RecordedClaimsMismatch { claim: "scope" }
    );
    let committed = consistency_error(
        |_| {},
        |context| {
            context["anchor"]["claims"]["client_id"] = json!({
                "commit": format!("sha256:{}", "11".repeat(32)),
                "salt_ref": "anchor.claims.client_id"
            });
        },
    );
    assert_eq!(
        committed,
        RootConsistencyError::RecordedClaimsMismatch { claim: "client_id" }
    );
    let missing = consistency_error(|_| {}, |context| context["anchor"]["claims"] = json!({}));
    assert_eq!(
        missing,
        RootConsistencyError::RecordedClaimsMismatch { claim: "client_id" }
    );
}

#[test]
fn artifact_retention_must_match_the_rule() {
    let error = consistency_error(
        |_| {},
        |context| context["anchor"]["artifact_retained"] = json!(true),
    );
    assert_eq!(error, RootConsistencyError::ArtifactRetentionMismatch);
}

fn snapshot_signed_by(exchange_key: &PublicKey, signer: &Keypair) -> IdpKeySnapshot {
    let unsigned: IdpKeySnapshot = serde_json::from_value(json!({
        "schema": "chio.idp-key-snapshot.v1",
        "issuer": "https://acme.okta.com",
        "source": "https://acme.okta.com/oauth2/v1/keys",
        "keys": [{ "kid": "k-okta-1", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }],
        "observed_at": NOW,
        "exchange_key": exchange_key,
        "signature": "00".repeat(64)
    }))
    .unwrap();
    let signature = signer.sign_canonical(&unsigned.signing_body()).unwrap().0;
    let mut fields = unsigned.into_fields();
    fields.signature = signature;
    IdpKeySnapshot::new(fields).unwrap()
}

fn static_bearer_policy(ceiling_tools: &[&str]) -> impl FnOnce(&mut Value) {
    let ceiling = scope(ceiling_tools.iter().map(|tool| grant(tool)).collect());
    move |policy| {
        let mut rule = static_bearer_rule_json("dev-static");
        rule["ceiling_scope"] = serde_json::to_value(&ceiling).unwrap();
        rule["ceiling_scope_hash"] = serde_json::to_value(scope_digest(&ceiling)).unwrap();
        policy["rules"].as_array_mut().unwrap().push(rule);
    }
}

fn static_bearer_context(token_exp: u64) -> impl FnOnce(&mut Value) {
    move |context| {
        context["anchor"] = json!({
            "kind": "operator_static_bearer",
            "issuer": "urn:chio:operator",
            "artifact_retained": false,
            "replay_key_digest": format!("sha256:{}", "a8".repeat(32)),
            "token_iat": ISSUED_AT,
            "token_exp": token_exp,
            "subject": { "commit": format!("sha256:{}", "55".repeat(32)), "salt_ref": "anchor.sub" },
            "tenant": { "commit": format!("sha256:{}", "69".repeat(32)), "salt_ref": "anchor.tenant" },
            "claims": {}
        });
        context["root_policy_rule_id"] = json!("dev-static");
    }
}

#[test]
fn static_bearer_root_scoped_to_its_ceiling_agrees() {
    let fixture = Fixture::with(
        static_bearer_policy(&["search"]),
        static_bearer_context(EXPIRES_AT),
        &exchange_keypair(),
        vec![grant("search")],
    );
    assert_eq!(fixture.check(), Ok(()));
}

#[test]
fn static_bearer_assertion_exp_must_equal_the_root_expiry() {
    let error = Fixture::with(
        static_bearer_policy(&["search"]),
        static_bearer_context(EXPIRES_AT + 10),
        &exchange_keypair(),
        vec![grant("search")],
    )
    .check()
    .unwrap_err();
    assert_eq!(
        error,
        RootConsistencyError::StaticBearerExpiryMismatch {
            expires_at: EXPIRES_AT,
            assertion_exp: EXPIRES_AT + 10,
        }
    );
}

#[test]
fn static_bearer_root_narrower_than_its_ceiling_denies() {
    let error = Fixture::with(
        static_bearer_policy(&["search", "get"]),
        static_bearer_context(EXPIRES_AT),
        &exchange_keypair(),
        vec![grant("search")],
    )
    .check()
    .unwrap_err();
    assert_eq!(error, RootConsistencyError::StaticBearerScopeNotCeiling);
}

#[test]
fn inverted_assertion_window_denies() {
    let error = consistency_error(
        |_| {},
        |context| context["anchor"]["token_iat"] = json!(EXPIRES_AT + 1),
    );
    assert_eq!(
        error,
        RootConsistencyError::InvertedAssertionWindow {
            token_iat: EXPIRES_AT + 1,
            token_exp: EXPIRES_AT,
        }
    );
}

#[test]
fn anchor_algorithm_outside_the_rule_denies() {
    let error = consistency_error(|_| {}, |context| context["anchor"]["alg"] = json!("ES256"));
    assert_eq!(error, RootConsistencyError::AlgorithmNotAllowed);
}

#[test]
fn budget_share_marker_is_not_a_root() {
    let mut fixture = Fixture::new();
    fixture.root.budget_share_bps = Some(5_000);
    assert_eq!(fixture.check(), Err(RootConsistencyError::NotARoot));
}

#[test]
fn scope_attenuation_marker_is_not_a_root() {
    let mut fixture = Fixture::new();
    fixture.root.scope_attenuations = Some(vec![Attenuation::RemoveTool {
        server_id: "crm".into(),
        tool_name: "get".into(),
    }]);
    assert_eq!(fixture.check(), Err(RootConsistencyError::NotARoot));
}

#[test]
fn policy_load_refuses_a_weak_exchange_key() {
    let weak = "0100000000000000000000000000000000000000000000000000000000000000";
    let error = load(signed_policy(|policy| {
        policy["exchange_keys"] = json!([exchange_keypair().public_key(), weak]);
    }))
    .unwrap_err();
    assert_eq!(error, RootPolicyLoadError::WeakExchangeKey);
}

#[test]
fn policy_load_refuses_the_policy_key_as_an_exchange_key() {
    let error = load(signed_policy(|policy| {
        policy["exchange_keys"] = json!([
            exchange_keypair().public_key(),
            policy_keypair().public_key()
        ]);
    }))
    .unwrap_err();
    assert_eq!(error, RootPolicyLoadError::PolicyKeyIsExchangeKey);
}

#[test]
fn key_snapshot_verifies_under_the_pinned_exchange_key() {
    let pinned = exchange_keypair().public_key();
    let snapshot = snapshot_signed_by(&pinned, &exchange_keypair());
    assert_eq!(snapshot.verify_signature(&pinned), Ok(()));
}

#[test]
fn key_snapshot_signed_by_a_key_that_is_not_pinned_is_refused() {
    let pinned = exchange_keypair().public_key();
    let self_asserted = snapshot_signed_by(&other_keypair().public_key(), &other_keypair());
    assert_eq!(
        self_asserted.verify_signature(&pinned),
        Err(IdpKeySnapshotSignatureError::ExchangeKeyNotPinned)
    );
    let forged = snapshot_signed_by(&pinned, &other_keypair());
    assert_eq!(
        forged.verify_signature(&pinned),
        Err(IdpKeySnapshotSignatureError::InvalidSignature)
    );
}

#[test]
fn key_snapshot_digest_is_domain_separated_and_covers_the_signature() {
    let pinned = exchange_keypair().public_key();
    let snapshot = snapshot_signed_by(&pinned, &exchange_keypair());
    let mut preimage = b"chio.idp-key-snapshot.v1\0".to_vec();
    preimage.extend_from_slice(&canonical_json_bytes(&snapshot).unwrap());
    assert_eq!(
        snapshot.digest().unwrap(),
        Sha256Digest::from_hash(sha256(&preimage))
    );
    let resigned = snapshot_signed_by(&pinned, &other_keypair());
    assert_ne!(resigned.digest().unwrap(), snapshot.digest().unwrap());
}

#[test]
fn key_snapshot_digest_vector() {
    let snapshot = snapshot_signed_by(&exchange_keypair().public_key(), &exchange_keypair());
    assert_eq!(
        snapshot.digest().unwrap().to_string(),
        "sha256:01d8735e11a090cb4dba74f1c62ab185d6eaa9efb97a69b580e209a69e5805f7"
    );
}

#[test]
fn registry_snapshot_source_refuses_a_byte_order_mark() {
    assert_eq!(
        KeySnapshotSource::parse("registry:acme\u{feff}okta").unwrap_err(),
        RootAuthorityShapeError::Pattern {
            field: "source",
            expected: "registry:<1 to 128 characters without NUL or whitespace>",
        }
    );
    assert!(KeySnapshotSource::parse("registry:acme-okta").is_ok());
}
