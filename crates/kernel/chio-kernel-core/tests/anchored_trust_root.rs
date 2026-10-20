//! Depth-0 anchored-root verification against a pinned exchange key and root policy.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::anchor::RootAnchor;
use chio_core_types::capability::crypto_floor::CapabilityCryptoFloor;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::Keypair;
use chio_core_types::root_authority::{
    DelegationContext, HolderClass, LoadedRootPolicy, RootBindingError, RootPolicy,
    RootPolicyLoadError, Sha256Digest,
};
use chio_core_types::{canonical_json_bytes, sha256};
use chio_kernel_core::{
    AnchoredRootError, AnchoredTrustRoot, CapabilityError, FixedClock, TrustRootResolver,
};
use serde_json::json;

const NOW: u64 = 1_792_234_800;
const ISSUED_AT: u64 = NOW - 5;
const EXPIRES_AT: u64 = NOW + 290;
const VALID_FROM: u64 = NOW - 1_000;
const VALID_UNTIL: u64 = NOW + 100_000;

fn policy_keypair() -> Keypair {
    Keypair::from_seed(&[1; 32])
}

fn exchange_keypair() -> Keypair {
    Keypair::from_seed(&[2; 32])
}

fn other_keypair() -> Keypair {
    Keypair::from_seed(&[3; 32])
}

fn crm_scope(tools: &[&str]) -> ChioScope {
    ChioScope {
        grants: tools
            .iter()
            .map(|tool| ToolGrant {
                server_id: "crm".into(),
                tool_name: (*tool).into(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            })
            .collect(),
        ..ChioScope::default()
    }
}

fn scope_digest(scope: &ChioScope) -> Sha256Digest {
    Sha256Digest::from_hash(sha256(&canonical_json_bytes(scope).unwrap()))
}

fn loaded_policy() -> LoadedRootPolicy {
    let ceiling = crm_scope(&["search", "get"]);
    let mut policy: RootPolicy = serde_json::from_value(json!({
        "schema": "chio.root-policy.v1",
        "policy_id": "rp_acme_prod",
        "policy_key": policy_keypair().public_key(),
        "exchange_keys": [exchange_keypair().public_key()],
        "rules": [{
            "rule_id": "dev-static",
            "match": { "anchor_kind": "operator_static_bearer" },
            "ceiling_scope": ceiling,
            "ceiling_scope_hash": scope_digest(&ceiling),
            "recorded_claims": {},
            "holder_classes": ["edge_session"],
            "principal": "dev:alice",
            "tenant_value": "dev"
        }],
        "disclosure": { "default": "committed" },
        "valid_from": VALID_FROM,
        "valid_until": VALID_UNTIL,
        "signature": "00".repeat(64)
    }))
    .unwrap();
    policy.signature = policy_keypair()
        .sign_canonical(&policy.signing_body())
        .unwrap()
        .0;
    policy.load(&policy_keypair().public_key(), NOW).unwrap()
}

struct Fixture {
    policy: LoadedRootPolicy,
    context: DelegationContext,
    root: CapabilityToken,
    anchor: RootAnchor,
}

impl Fixture {
    fn signed_by(signer: &Keypair) -> Self {
        let policy = loaded_policy();
        let root_scope = crm_scope(&["search"]);
        let context: DelegationContext = serde_json::from_value(json!({
            "schema": "chio.delegation-context.v1",
            "anchor": {
                "kind": "operator_static_bearer",
                "issuer": "urn:chio:operator",
                "artifact_retained": false,
                "replay_key_digest": format!("sha256:{}", "a8".repeat(32)),
                "token_iat": ISSUED_AT,
                "token_exp": EXPIRES_AT,
                "subject": { "commit": format!("sha256:{}", "55".repeat(32)), "salt_ref": "anchor.sub" },
                "tenant": { "commit": format!("sha256:{}", "69".repeat(32)), "salt_ref": "anchor.tenant" },
                "claims": {}
            },
            "exchange": {
                "exchange_key": signer.public_key(),
                "exchanged_at": ISSUED_AT,
                "request_digest": format!("sha256:{}", "82".repeat(32)),
                "holder": "edge_session"
            },
            "root_policy_rule_id": "dev-static",
            "effective_root_scope_hash": scope_digest(&root_scope)
        }))
        .unwrap();
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
            anchored_at: ISSUED_AT,
            assertion_exp: EXPIRES_AT,
        };
        Self {
            policy,
            context,
            root,
            anchor,
        }
    }

    fn new() -> Self {
        Self::signed_by(&exchange_keypair())
    }

    fn verify_at(
        &self,
        now: u64,
    ) -> Result<chio_kernel_core::VerifiedAnchoredRoot, AnchoredRootError> {
        let exchange_key = exchange_keypair().public_key();
        AnchoredTrustRoot::new(&exchange_key, &self.policy)?.verify_root(
            &self.root,
            &self.anchor,
            &self.context,
            None,
            &FixedClock::new(now),
            CapabilityCryptoFloor::AllowClassical,
        )
    }
}

#[test]
fn exchange_issued_root_verifies() {
    let fixture = Fixture::new();
    let verified = fixture.verify_at(NOW).unwrap();
    assert_eq!(verified.capability().id(), "cap-root");
    assert_eq!(verified.anchor(), &fixture.anchor);
    assert_eq!(verified.rule_id().as_str(), "dev-static");
    assert_eq!(verified.holder(), HolderClass::EdgeSession);
    assert_eq!(
        verified.effective_root_scope_hash(),
        &fixture.context.effective_root_scope_hash
    );
    assert_eq!(
        verified.trust_root_scope_hash(&exchange_keypair().public_key()),
        Some(fixture.context.effective_root_scope_hash.to_bare_hex())
    );
    assert_eq!(
        verified.trust_root_scope_hash(&other_keypair().public_key()),
        None
    );
}

#[test]
fn exchange_key_outside_the_policy_is_refused() {
    let fixture = Fixture::new();
    let unlisted = other_keypair().public_key();
    let error = AnchoredTrustRoot::new(&unlisted, &fixture.policy).unwrap_err();
    assert_eq!(error, AnchoredRootError::ExchangeKeyNotInPolicy);
}

#[test]
fn root_signed_by_another_key_is_refused() {
    let error = Fixture::signed_by(&other_keypair())
        .verify_at(NOW)
        .unwrap_err();
    assert_eq!(error, AnchoredRootError::IssuerNotExchangeKey);
}

#[test]
fn policy_outside_its_window_refuses_every_root() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.verify_at(VALID_FROM - 1).unwrap_err(),
        AnchoredRootError::PolicyOutOfForce(RootPolicyLoadError::NotYetValid {
            valid_from: VALID_FROM
        })
    );
    assert_eq!(
        fixture.verify_at(VALID_UNTIL).unwrap_err(),
        AnchoredRootError::PolicyOutOfForce(RootPolicyLoadError::Expired {
            valid_until: VALID_UNTIL
        })
    );
}

#[test]
fn root_changed_after_signing_is_refused() {
    let mut fixture = Fixture::new();
    fixture.root.id = "cap-forged".into();
    assert_eq!(
        fixture.verify_at(NOW).unwrap_err(),
        AnchoredRootError::Capability(CapabilityError::InvalidSignature)
    );
}

#[test]
fn root_outside_its_lifetime_is_refused() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.verify_at(EXPIRES_AT).unwrap_err(),
        AnchoredRootError::Capability(CapabilityError::Expired)
    );
    assert_eq!(
        fixture.verify_at(ISSUED_AT - 1).unwrap_err(),
        AnchoredRootError::Capability(CapabilityError::NotYetValid)
    );
}

#[test]
fn broken_binding_is_refused() {
    let mut fixture = Fixture::new();
    fixture.anchor.assertion_exp += 1;
    assert_eq!(
        fixture.verify_at(NOW).unwrap_err(),
        AnchoredRootError::Binding(RootBindingError::AssertionExpMismatch)
    );
}
