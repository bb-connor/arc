use super::super::super::*;
use super::super::pinned_authority::PinnedControlAuthority;
use super::super::remote_root_resolver::RemoteAggregateFamilyRootResolver;
use super::support::{assert_bearer_request, ScriptedResponse, ScriptedResponseServer};
use chio_core::capability::aggregate_budget::{
    issue_aggregate_family_root, AggregateFamilyRootResolution, AggregateFamilyRootResolutionError,
};
use chio_core::capability::scope::{Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_test_support::prelude::*;

fn legacy_root(id: &str, issuer: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: Keypair::generate().public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "remote-root-server".to_string(),
                    tool_name: "remote-root-tool".to_string(),
                    operations: vec![Operation::Invoke, Operation::Delegate],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: 1_000,
            expires_at: 4_000_000_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .test_unwrap()
}

fn token_digest(canonical_token: &[u8]) -> String {
    let mut preimage = b"chio.aggregate-family-root-record.v1\0".to_vec();
    preimage.extend_from_slice(canonical_token);
    sha256_hex(&preimage)
}

fn pinned_authority(
    current: &Keypair,
    historical: Vec<chio_core::PublicKey>,
) -> PinnedControlAuthority {
    PinnedControlAuthority::new(current.public_key(), historical).test_unwrap()
}

fn signed_lookup(
    issuer: &Keypair,
    nonce: &str,
    root_id: &str,
    outcome: AggregateFamilyRootLookupOutcome,
    high_watermark: Option<u64>,
) -> String {
    let now = unix_timestamp_now();
    let body = AggregateFamilyRootLookupBody {
        schema: AGGREGATE_FAMILY_ROOT_LOOKUP_SCHEMA.to_string(),
        endpoint: AGGREGATE_FAMILY_ROOT_LOOKUP_PATH.to_string(),
        source_node_id: "http://127.0.0.1".to_string(),
        request_nonce: nonce.to_string(),
        requested_root_capability_id: root_id.to_string(),
        issued_at: now,
        expires_at: now + 30,
        authority_generation: 1,
        authority_rotated_at: 900,
        consistency: AggregateFamilyRootReadConsistency::Standalone,
        high_watermark,
        outcome,
    };
    let signed = SignedAggregateFamilyRootLookup::sign(body, issuer).test_unwrap();
    String::from_utf8(canonical_json_bytes(&signed).test_unwrap()).test_unwrap()
}

#[test]
fn remote_aggregate_family_root_resolver_authenticates_exact_legacy_root() {
    let issuer = Keypair::generate();
    let token = legacy_root("root/a", &issuer);
    let canonical_token = canonical_json_bytes(&token).test_unwrap();
    let nonce = "ab".repeat(32);
    let lookup = signed_lookup(
        &issuer,
        &nonce,
        &token.id,
        AggregateFamilyRootLookupOutcome::Found {
            source_seq: 1,
            canonical_token_json: String::from_utf8(canonical_token.clone()).test_unwrap(),
            token_digest: token_digest(&canonical_token),
        },
        Some(1),
    );
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: lookup,
        content_type: "application/json",
    }]);
    let resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &server.url,
        "secret",
        pinned_authority(&issuer, Vec::new()),
    )
    .test_unwrap();

    assert!(matches!(
        resolver.resolve_with_nonce(&token.id, &nonce),
        Ok(AggregateFamilyRootResolution::LegacyUnbound(root))
            if root.root_capability_id() == token.id
    ));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_bearer_request(
        &requests[0],
        "GET",
        "/v1/aggregate-family-roots/root%2Fa",
        &["nonce=abab"],
    );
}

#[test]
fn remote_aggregate_family_root_resolver_authenticates_family_binding() {
    let issuer = Keypair::generate();
    let unsigned = legacy_root("family-root", &issuer);
    let token = issue_aggregate_family_root(unsigned.body(), 7, &issuer).test_unwrap();
    let canonical_token = canonical_json_bytes(&token).test_unwrap();
    let nonce = "78".repeat(32);
    let lookup = signed_lookup(
        &issuer,
        &nonce,
        &token.id,
        AggregateFamilyRootLookupOutcome::Found {
            source_seq: 1,
            canonical_token_json: String::from_utf8(canonical_token.clone()).test_unwrap(),
            token_digest: token_digest(&canonical_token),
        },
        Some(1),
    );
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: lookup,
        content_type: "application/json",
    }]);
    let resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &server.url,
        "secret",
        pinned_authority(&issuer, Vec::new()),
    )
    .test_unwrap();

    assert!(matches!(
        resolver.resolve_with_nonce(&token.id, &nonce),
        Ok(AggregateFamilyRootResolution::FamilyBound(root))
            if root.root_capability_id() == token.id && root.max_invocations() == 7
    ));
}

#[test]
fn remote_aggregate_family_root_resolver_rejects_unproven_absence_and_replay() {
    let issuer = Keypair::generate();
    let nonce = "cd".repeat(32);
    let lookup = signed_lookup(
        &issuer,
        &nonce,
        "missing-root",
        AggregateFamilyRootLookupOutcome::Missing,
        Some(0),
    );
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: lookup,
        content_type: "application/json",
    }]);
    let resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &server.url,
        "secret",
        pinned_authority(&issuer, Vec::new()),
    )
    .test_unwrap();

    assert!(matches!(
        resolver.resolve_with_nonce("missing-root", &nonce),
        Err(AggregateFamilyRootResolutionError::Unavailable(_))
    ));

    let replay_server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: signed_lookup(
            &issuer,
            &nonce,
            "missing-root",
            AggregateFamilyRootLookupOutcome::Missing,
            Some(0),
        ),
        content_type: "application/json",
    }]);
    let replay_resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &replay_server.url,
        "secret",
        pinned_authority(&issuer, Vec::new()),
    )
    .test_unwrap();
    assert!(matches!(
        replay_resolver.resolve_with_nonce("missing-root", &"ef".repeat(32)),
        Err(AggregateFamilyRootResolutionError::Corrupt(_))
    ));
}

#[test]
fn remote_aggregate_family_root_resolver_rejects_malformed_authenticated_results() {
    let issuer = Keypair::generate();
    let attacker = Keypair::generate();
    let token = legacy_root("expected-root", &issuer);
    let wrong_token = legacy_root("wrong-root", &issuer);
    let untrusted_token = legacy_root("expected-root", &attacker);
    let nonce = "12".repeat(32);
    let canonical_token = canonical_json_bytes(&token).test_unwrap();
    let wrong_canonical = canonical_json_bytes(&wrong_token).test_unwrap();
    let untrusted_canonical = canonical_json_bytes(&untrusted_token).test_unwrap();

    let valid = signed_lookup(
        &issuer,
        &nonce,
        &token.id,
        AggregateFamilyRootLookupOutcome::Found {
            source_seq: 1,
            canonical_token_json: String::from_utf8(canonical_token.clone()).test_unwrap(),
            token_digest: token_digest(&canonical_token),
        },
        Some(1),
    );
    let mut unknown_value: Value = serde_json::from_str(&valid).test_unwrap();
    unknown_value
        .as_object_mut()
        .test_unwrap()
        .insert("unknown".to_string(), Value::Bool(true));
    let cases = vec![
        signed_lookup(
            &issuer,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Found {
                source_seq: 1,
                canonical_token_json: String::from_utf8(canonical_token).test_unwrap(),
                token_digest: "0".repeat(64),
            },
            Some(1),
        ),
        signed_lookup(
            &issuer,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Found {
                source_seq: 1,
                canonical_token_json: String::from_utf8(wrong_canonical.clone()).test_unwrap(),
                token_digest: token_digest(&wrong_canonical),
            },
            Some(1),
        ),
        signed_lookup(
            &attacker,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Missing,
            Some(0),
        ),
        signed_lookup(
            &issuer,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Found {
                source_seq: 1,
                canonical_token_json: String::from_utf8(untrusted_canonical.clone()).test_unwrap(),
                token_digest: token_digest(&untrusted_canonical),
            },
            Some(1),
        ),
        serde_json::to_string_pretty(
            &serde_json::from_str::<SignedAggregateFamilyRootLookup>(&valid).test_unwrap(),
        )
        .test_unwrap(),
        chio_core::canonicalize(&unknown_value).test_unwrap(),
    ];

    for body in cases {
        let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
            status: 200,
            body,
            content_type: "application/json",
        }]);
        let resolver = RemoteAggregateFamilyRootResolver::new_for_test(
            &server.url,
            "secret",
            pinned_authority(&issuer, Vec::new()),
        )
        .test_unwrap();
        assert!(matches!(
            resolver.resolve_with_nonce(&token.id, &nonce),
            Err(AggregateFamilyRootResolutionError::Corrupt(_))
        ));
    }
}

#[test]
fn remote_aggregate_family_root_resolver_separates_unavailable_and_transport_policy() {
    let issuer = Keypair::generate();
    let nonce = "34".repeat(32);
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 404,
        body: "route unavailable".to_string(),
        content_type: "text/plain",
    }]);
    let resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &server.url,
        "secret",
        pinned_authority(&issuer, Vec::new()),
    )
    .test_unwrap();
    assert!(matches!(
        resolver.resolve_with_nonce("missing-root", &nonce),
        Err(AggregateFamilyRootResolutionError::Unavailable(_))
    ));

    let error = match RemoteAggregateFamilyRootResolver::new_with_pinned_authority(
        "http://control.example.test",
        "secret",
        pinned_authority(&issuer, Vec::new()),
    ) {
        Ok(_) => panic!("non-loopback cleartext root resolution must reject"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("requires HTTPS"));

    let loopback_error = match RemoteAggregateFamilyRootResolver::new_with_pinned_authority(
        "http://127.0.0.1:9",
        "secret",
        pinned_authority(&issuer, Vec::new()),
    ) {
        Ok(_) => panic!("production loopback cleartext root resolution must reject"),
        Err(error) => error,
    };
    assert!(loopback_error.to_string().contains("requires HTTPS"));
}

#[test]
fn remote_aggregate_family_root_resolver_rejects_oversized_and_unknown_authority_state() {
    let issuer = Keypair::generate();
    let nonce = "56".repeat(32);
    let oversized = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: " ".repeat(AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_BYTES as usize + 1),
        content_type: "application/json",
    }]);
    let oversized_resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &oversized.url,
        "secret",
        pinned_authority(&issuer, Vec::new()),
    )
    .test_unwrap();
    assert!(matches!(
        oversized_resolver.resolve_with_nonce("missing-root", &nonce),
        Err(AggregateFamilyRootResolutionError::Corrupt(_))
    ));

    let valid = signed_lookup(
        &issuer,
        &nonce,
        "missing-root",
        AggregateFamilyRootLookupOutcome::Missing,
        Some(0),
    );
    let mut unknown: Value = serde_json::from_str(&valid).test_unwrap();
    unknown
        .as_object_mut()
        .test_unwrap()
        .insert("unknown".to_string(), Value::Bool(true));
    let unknown_response = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: chio_core::canonicalize(&unknown).test_unwrap(),
        content_type: "application/json",
    }]);
    let response_resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &unknown_response.url,
        "secret",
        pinned_authority(&issuer, Vec::new()),
    )
    .test_unwrap();
    assert!(matches!(
        response_resolver.resolve_with_nonce("missing-root", &nonce),
        Err(AggregateFamilyRootResolutionError::Corrupt(_))
    ));
}

#[test]
fn remote_aggregate_family_root_resolver_rejects_self_declared_attacker_authority() {
    let pinned = Keypair::generate();
    let attacker = Keypair::generate();
    let token = legacy_root("forged-root", &attacker);
    let canonical_token = canonical_json_bytes(&token).test_unwrap();
    let nonce = "90".repeat(32);
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: signed_lookup(
            &attacker,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Found {
                source_seq: 1,
                canonical_token_json: String::from_utf8(canonical_token.clone()).test_unwrap(),
                token_digest: token_digest(&canonical_token),
            },
            Some(1),
        ),
        content_type: "application/json",
    }]);
    let resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &server.url,
        "secret",
        pinned_authority(&pinned, Vec::new()),
    )
    .test_unwrap();

    assert!(matches!(
        resolver.resolve_with_nonce(&token.id, &nonce),
        Err(AggregateFamilyRootResolutionError::Corrupt(_))
    ));
}

#[test]
fn remote_aggregate_family_root_resolver_separates_current_signer_from_historical_roots() {
    let previous = Keypair::generate();
    let current = Keypair::generate();
    let token = legacy_root("pre-rotation-root", &previous);
    let canonical_token = canonical_json_bytes(&token).test_unwrap();
    let nonce = "91".repeat(32);
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: signed_lookup(
            &current,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Found {
                source_seq: 1,
                canonical_token_json: String::from_utf8(canonical_token.clone()).test_unwrap(),
                token_digest: token_digest(&canonical_token),
            },
            Some(1),
        ),
        content_type: "application/json",
    }]);
    let resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, vec![previous.public_key()]),
    )
    .test_unwrap();

    assert!(matches!(
        resolver.resolve_with_nonce(&token.id, &nonce),
        Ok(AggregateFamilyRootResolution::LegacyUnbound(root))
            if root.root_capability_id() == token.id
    ));

    let stale_server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: signed_lookup(
            &previous,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Found {
                source_seq: 1,
                canonical_token_json: String::from_utf8(canonical_token.clone()).test_unwrap(),
                token_digest: token_digest(&canonical_token),
            },
            Some(1),
        ),
        content_type: "application/json",
    }]);
    let stale_resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &stale_server.url,
        "secret",
        pinned_authority(&current, vec![previous.public_key()]),
    )
    .test_unwrap();
    assert!(matches!(
        stale_resolver.resolve_with_nonce(&token.id, &nonce),
        Err(AggregateFamilyRootResolutionError::Corrupt(_))
    ));
}

#[test]
fn remote_aggregate_family_root_resolver_validates_each_failover_endpoint() {
    let current = Keypair::generate();
    let stale = Keypair::generate();
    let token = legacy_root("failover-root", &current);
    let canonical_token = canonical_json_bytes(&token).test_unwrap();
    let nonce = "92".repeat(32);
    let stale_server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: signed_lookup(
            &stale,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Missing,
            Some(0),
        ),
        content_type: "application/json",
    }]);
    let current_server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: signed_lookup(
            &current,
            &nonce,
            &token.id,
            AggregateFamilyRootLookupOutcome::Found {
                source_seq: 1,
                canonical_token_json: String::from_utf8(canonical_token.clone()).test_unwrap(),
                token_digest: token_digest(&canonical_token),
            },
            Some(1),
        ),
        content_type: "application/json",
    }]);
    let resolver = RemoteAggregateFamilyRootResolver::new_for_test(
        &format!("{},{}", stale_server.url, current_server.url),
        "secret",
        pinned_authority(&current, vec![stale.public_key()]),
    )
    .test_unwrap();

    assert!(matches!(
        resolver.resolve_with_nonce(&token.id, &nonce),
        Ok(AggregateFamilyRootResolution::LegacyUnbound(root))
            if root.root_capability_id() == token.id
    ));
    assert_eq!(stale_server.requests().len(), 1);
    assert_eq!(current_server.requests().len(), 1);
}
