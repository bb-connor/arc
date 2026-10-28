use std::collections::BTreeMap;

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::rng::{Rng, RngError};
use chio_core::root_authority::{RootPolicy, Sha256Digest};
use chio_core::{canonical_json_bytes, sha256, Keypair};
use chio_test_support::prelude::*;
use serde_json::json;

use super::kinds::operator_static_bearer::{self, StaticBearerToken};
use super::{ClientRegistry, PreparedAnchoredRoot, RootExchange, RootExchangeConfig};

const NOW: u64 = 1_792_234_800;
const SUBJECT: &str = "operator:alice";
const TENANT: &str = "tenant-acme";

struct FixedSalt;

impl Rng for FixedSalt {
    fn fill_bytes(&self, bytes: &mut [u8]) -> Result<(), RngError> {
        bytes.fill(0x5a);
        Ok(())
    }
}

fn prepared() -> PreparedAnchoredRoot {
    let policy_key = Keypair::from_seed(&[1; 32]);
    let exchange_key = Keypair::from_seed(&[2; 32]);
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "crm".into(),
            tool_name: "search".into(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let scope_hash = Sha256Digest::from_hash(sha256(
        &canonical_json_bytes(&scope).test_expect("canonical scope"),
    ));
    let unsigned: RootPolicy = serde_json::from_value(json!({
        "schema": "chio.root-policy.v1",
        "policy_id": "rp_commitment_vectors",
        "policy_key": policy_key.public_key(),
        "exchange_keys": [exchange_key.public_key()],
        "rules": [{
            "rule_id": "operator-vector",
            "match": {"anchor_kind": "operator_static_bearer"},
            "principal": SUBJECT,
            "tenant_value": TENANT,
            "ceiling_scope": scope,
            "ceiling_scope_hash": scope_hash,
            "recorded_claims": {},
            "holder_classes": ["edge_session"],
            "capability_ttl_secs": 300,
            "max_clock_skew_secs": 30
        }],
        "disclosure": {"default": "committed"},
        "valid_from": NOW - 1_000,
        "valid_until": NOW + 1_000,
        "signature": "00".repeat(64)
    }))
    .test_expect("policy shape");
    let signature = policy_key
        .sign_canonical(&unsigned.signing_body())
        .test_expect("sign policy")
        .0;
    let mut fields = unsigned.into_fields();
    fields.signature = signature;
    let policy = RootPolicy::new(fields)
        .test_expect("signed policy")
        .load(&policy_key.public_key(), NOW)
        .test_expect("verify policy against pinned key");
    let exchange = RootExchange::new(RootExchangeConfig {
        policy,
        providers: BTreeMap::new(),
        clients: ClientRegistry::new(&[]).test_expect("empty client registry"),
        exchange_key: exchange_key.public_key(),
        authorization_server: "https://exchange.example".into(),
        token_endpoint: "https://exchange.example/token".into(),
        protected_resource: "https://exchange.example/mcp".into(),
        client_assertion_skew_secs: 5,
    })
    .test_expect("exchange configuration");
    let configured = StaticBearerToken::new("operator-vector-token");
    let evidence =
        operator_static_bearer::verify(&exchange, &configured, "operator-vector-token", NOW)
            .test_expect("verify configured bearer");
    exchange
        .prepare(evidence, None, None, NOW, &FixedSalt)
        .test_expect("prepare anchored root")
}

fn assert_commitment(reference: &str, value: &str, domain: &[u8]) {
    let prepared = prepared();
    let anchor = &prepared.context().anchor;
    let commitment = match reference {
        "anchor.sub" => &anchor.subject,
        "anchor.tenant" => &anchor.tenant,
        _ => unreachable!(),
    };
    assert_eq!(commitment.salt_ref.as_str(), reference);
    let openings: Vec<_> = prepared
        .openings()
        .iter()
        .filter(|opening| opening.salt_ref.as_str() == reference)
        .collect();
    assert_eq!(openings.len(), 1);
    let opening = openings[0];
    assert_eq!(opening.value, json!(value));
    assert_eq!(opening.salt, [0x5a; 32]);
    let preimage = [domain, opening.salt.as_slice(), value.as_bytes()].concat();
    assert_eq!(
        commitment.commit,
        Sha256Digest::from_hash(sha256(&preimage))
    );
}

#[test]
fn subject_commitment_matches_literal_domain_salt_and_utf8() {
    assert_commitment(
        "anchor.sub",
        SUBJECT,
        b"chio.delegation-context.subject.v1\0",
    );
}

#[test]
fn tenant_commitment_matches_literal_domain_salt_and_utf8() {
    assert_commitment(
        "anchor.tenant",
        TENANT,
        b"chio.delegation-context.tenant.v1\0",
    );
}
