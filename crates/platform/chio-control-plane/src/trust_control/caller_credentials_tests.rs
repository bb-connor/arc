use super::*;
use chio_test_support::prelude::*;

pub(crate) const DEPLOYMENT: &str = "dep-a";

pub(crate) fn digest(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

pub(crate) fn credential(
    id: &str,
    kind: &str,
    secret: &str,
    scopes: &[&str],
    tenant: Option<&str>,
) -> String {
    let scopes = scopes
        .iter()
        .map(|scope| format!("\"{scope}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let tenant_authority = match tenant {
        None => "\"deployment\"".to_string(),
        Some(tenant) => format!("{{ tenant = \"{tenant}\" }}"),
    };
    format!(
        "[[credentials]]\nid = \"{id}\"\nkind = \"{kind}\"\nsecret_sha256 = \"{}\"\nscopes = [{scopes}]\ndeployment = \"{DEPLOYMENT}\"\ntenant_authority = {tenant_authority}\n",
        digest(secret)
    )
}

pub(crate) fn peer(node_id: &str, keypair: &Keypair, scopes: &[&str]) -> String {
    let scopes = scopes
        .iter()
        .map(|scope| format!("\"{scope}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[[cluster.peers]]\nnode_id = \"{node_id}\"\ninternal_url = \"{node_id}\"\npublic_key = \"{}\"\nscopes = [{scopes}]\n",
        keypair.public_key().to_hex()
    )
}

pub(crate) fn config(body: &str) -> String {
    format!("deployment = \"{DEPLOYMENT}\"\ninternal_listen = \"127.0.0.1:9101\"\n{body}")
}

fn reader() -> String {
    credential(
        "reader",
        "caller",
        "reader-secret",
        &["receipts:read"],
        None,
    )
}

fn refusal(text: &str) -> TrustAccessError {
    TrustAccessConfig::from_toml_str(text).test_unwrap_err()
}

fn bearer(secret: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {secret}")).test_unwrap(),
    );
    headers
}

#[test]
fn closed_scope_set_round_trips_every_name() {
    assert_eq!(Scope::ALL.len(), 40);
    for scope in Scope::ALL {
        assert_eq!(Scope::parse(scope.as_str()), Some(*scope));
    }
    assert_eq!(Scope::parse("receipts:write"), None);
    assert_eq!(Scope::parse("RECEIPTS:READ"), None);
}

#[test]
fn old_config_keys_refuse_at_startup() {
    let service_token = refusal(&config(&format!("service_token = \"t\"\n{}", reader())));
    assert_eq!(service_token, TrustAccessError::RemovedKey("service_token"));
    assert_eq!(
        service_token.to_string(),
        "trust-control configuration key \"service_token\" is removed; declare [[credentials]] entries with scopes and tenant authority instead"
    );
    let tenant_tokens = refusal(&config(&format!(
        "tenant_read_tokens = {{ tenant-a = \"t\" }}\n{}",
        reader()
    )));
    assert_eq!(
        tenant_tokens,
        TrustAccessError::RemovedKey("tenant_read_tokens")
    );
    assert_eq!(
        tenant_tokens.to_string(),
        "trust-control configuration key \"tenant_read_tokens\" is removed; declare [[credentials]] entries with scopes and tenant authority instead"
    );
}

#[test]
fn credential_with_unknown_scope_refuses_at_startup() {
    let error = refusal(&config(&credential(
        "reader",
        "caller",
        "s",
        &["receipts:read", "receipts:everything"],
        None,
    )));
    assert_eq!(
        error,
        TrustAccessError::UnknownScope {
            credential: "reader".to_string(),
            scope: "receipts:everything".to_string(),
        }
    );
}

#[test]
fn credential_naming_another_deployment_refuses_at_startup() {
    let text = config(&reader().replace("deployment = \"dep-a\"", "deployment = \"dep-b\""));
    assert_eq!(
        refusal(&text),
        TrustAccessError::ForeignDeployment {
            credential: "reader".to_string(),
            credential_deployment: "dep-b".to_string(),
            deployment: DEPLOYMENT.to_string(),
        }
    );
}

#[test]
fn credential_shape_refusals_name_their_rule() {
    assert_eq!(refusal(&config("")), TrustAccessError::NoCredentials);
    let duplicate = format!(
        "{}{}",
        reader(),
        credential("reader", "caller", "other", &["reports:read"], None)
    );
    assert_eq!(
        refusal(&config(&duplicate)),
        TrustAccessError::DuplicateCredentialId("reader".to_string())
    );
    let shared_secret = format!(
        "{}{}",
        reader(),
        credential("second", "caller", "reader-secret", &["reports:read"], None)
    );
    assert_eq!(
        refusal(&config(&shared_secret)),
        TrustAccessError::DuplicateSecret("reader".to_string(), "second".to_string())
    );
    let upper = reader().replace(
        &digest("reader-secret"),
        &digest("reader-secret").to_uppercase(),
    );
    assert_eq!(
        refusal(&config(&upper)),
        TrustAccessError::InvalidSecretDigest("reader".to_string())
    );
    assert_eq!(
        refusal(&config(&credential("reader", "caller", "s", &[], None))),
        TrustAccessError::NoScopes("reader".to_string())
    );
    assert_eq!(
        refusal(&config(&credential(
            "reader",
            "caller",
            "s",
            &["receipts:read", "receipts:read"],
            None
        ))),
        TrustAccessError::DuplicateScope {
            credential: "reader".to_string(),
            scope: Scope::ReceiptsRead,
        }
    );
    assert_eq!(
        refusal(&config(&credential(
            "reader",
            "deployment",
            "s",
            &["cluster:replicate"],
            None
        ))),
        TrustAccessError::ClusterScopeOnCredential {
            credential: "reader".to_string(),
            scope: Scope::ClusterReplicate,
        }
    );
    assert_eq!(
        refusal(&config(&credential(
            "bad id",
            "caller",
            "s",
            &["receipts:read"],
            None
        ))),
        TrustAccessError::InvalidCredentialId("bad id".to_string())
    );
    let keyword = reader().replace("\"deployment\"\n", "\"tenant\"\n");
    assert_eq!(
        refusal(&config(&keyword)),
        TrustAccessError::InvalidTenantAuthority("reader".to_string())
    );
    assert!(matches!(
        refusal(&config(
            &reader().replace("kind = \"caller\"", "kind = \"admin\"")
        )),
        TrustAccessError::Malformed(_)
    ));
    assert!(matches!(
        refusal(&config(&format!("{}extra = 1\n", reader()))),
        TrustAccessError::Malformed(_)
    ));
}

#[test]
fn peer_shape_refusals_name_their_rule() {
    let keypair = Keypair::generate();
    let node = "https://node-b.example:9101";
    let with_peer = |peer_text: String| config(&format!("{}{peer_text}", reader()));
    assert_eq!(
        refusal(&with_peer(peer(node, &keypair, &["receipts:read"]))),
        TrustAccessError::PeerNonClusterScope {
            node_id: node.to_string(),
            scope: "receipts:read".to_string(),
        }
    );
    assert_eq!(
        refusal(&with_peer(peer(node, &keypair, &[]))),
        TrustAccessError::PeerNoScopes(node.to_string())
    );
    let twice = format!(
        "{}{}",
        peer(node, &keypair, &["cluster:replicate"]),
        peer(node, &Keypair::generate(), &["cluster:replicate"])
    );
    assert_eq!(
        refusal(&with_peer(twice)),
        TrustAccessError::DuplicatePeer(node.to_string())
    );
    let shared_key = format!(
        "{}{}",
        peer(node, &keypair, &["cluster:replicate"]),
        peer(
            "https://node-c.example:9101",
            &keypair,
            &["cluster:replicate"]
        )
    );
    assert_eq!(
        refusal(&with_peer(shared_key)),
        TrustAccessError::DuplicatePeerKey(
            node.to_string(),
            "https://node-c.example:9101".to_string()
        )
    );
    let bad_key =
        peer(node, &keypair, &["cluster:replicate"]).replace(&keypair.public_key().to_hex(), "zz");
    assert_eq!(
        refusal(&with_peer(bad_key)),
        TrustAccessError::InvalidPeerKey(node.to_string())
    );
}

#[test]
fn internal_listener_must_not_share_the_public_address() {
    let access = TrustAccessConfig::from_toml_str(&config(&reader())).test_unwrap();
    let shared: SocketAddr = "127.0.0.1:9101".parse().test_unwrap();
    assert_eq!(
        access.validate_listeners(shared).test_unwrap_err(),
        TrustAccessError::InternalListenerShared(shared)
    );
    access
        .validate_listeners("127.0.0.1:9100".parse().test_unwrap())
        .test_unwrap();
}

#[test]
fn validate_caller_requires_scope_and_known_secret() {
    let access = TrustAccessConfig::from_toml_str(&config(&reader())).test_unwrap();
    let caller = access
        .credentials
        .validate_caller(&bearer("reader-secret"), Scope::ReceiptsRead)
        .test_unwrap();
    assert_eq!(caller.credential_id, "reader");
    assert_eq!(caller.deployment, DEPLOYMENT);
    assert_eq!(caller.tenant_authority, TenantAuthority::Deployment);
    assert_eq!(
        access
            .credentials
            .validate_caller(&bearer("reader-secret"), Scope::ReportsRead)
            .test_unwrap_err(),
        CallerAuthError::MissingScope(Scope::ReportsRead)
    );
    assert_eq!(
        access
            .credentials
            .validate_caller(&bearer("other-secret"), Scope::ReceiptsRead)
            .test_unwrap_err(),
        CallerAuthError::Unauthenticated
    );
    assert_eq!(
        access
            .credentials
            .validate_caller(&HeaderMap::new(), Scope::ReceiptsRead)
            .test_unwrap_err(),
        CallerAuthError::Unauthenticated
    );
    let mut doubled = bearer("reader-secret");
    doubled.append(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer reader-secret"),
    );
    assert_eq!(
        access
            .credentials
            .validate_caller(&doubled, Scope::ReceiptsRead)
            .test_unwrap_err(),
        CallerAuthError::Unauthenticated
    );
}

#[test]
fn tenant_credential_limited_to_its_tenant() {
    let text = config(&credential(
        "tenant-a-reader",
        "caller",
        "tenant-a-secret",
        &["receipts:read", "reports:read"],
        Some("tenant-a"),
    ));
    let access = TrustAccessConfig::from_toml_str(&text).test_unwrap();
    let caller = access
        .credentials
        .validate_caller(&bearer("tenant-a-secret"), Scope::ReceiptsRead)
        .test_unwrap();
    assert_eq!(
        caller.tenant_authority,
        TenantAuthority::Tenant("tenant-a".to_string())
    );
    assert_eq!(
        caller.tenant_for_request(None).test_unwrap(),
        Some("tenant-a".to_string())
    );
    assert_eq!(
        caller.tenant_for_request(Some("tenant-a")).test_unwrap(),
        Some("tenant-a".to_string())
    );
    assert_eq!(
        caller
            .tenant_for_request(Some("tenant-b"))
            .test_unwrap_err(),
        CallerAuthError::CrossTenant
    );
    assert_eq!(
        caller.receipt_read_context(),
        chio_kernel::ReceiptReadContext::authenticated_tenant("tenant-a")
    );
}

#[test]
fn peer_signature_binds_node_path_query_and_time() {
    let keypair = Keypair::generate();
    let node = "https://node-b.example:9101";
    let access = TrustAccessConfig::from_toml_str(&config(&format!(
        "{}{}",
        reader(),
        peer(node, &keypair, &["cluster:replicate"])
    )))
    .test_unwrap();
    let target = PeerRequestTarget {
        method: "GET",
        path: "/v1/internal/revocations/delta",
        query: "afterSeq=7",
    };
    let issued_at = 1_792_234_800;
    let headers = signed_peer_headers(&keypair, node, &target, issued_at, Some(3));
    let peer = access
        .peers
        .verify(&headers, &target, issued_at, Scope::ClusterReplicate)
        .test_unwrap();
    assert_eq!(peer.node_id, node);
    assert_eq!(peer.term, Some(3));
    let moved = PeerRequestTarget {
        path: "/v1/internal/budgets/delta",
        ..target
    };
    assert_eq!(
        access
            .peers
            .verify(&headers, &moved, issued_at, Scope::ClusterReplicate)
            .test_unwrap_err(),
        PeerAuthError::BadSignature
    );
    let other_cursor = PeerRequestTarget {
        query: "afterSeq=0",
        ..target
    };
    assert_eq!(
        access
            .peers
            .verify(&headers, &other_cursor, issued_at, Scope::ClusterReplicate)
            .test_unwrap_err(),
        PeerAuthError::BadSignature
    );
    assert_eq!(
        access
            .peers
            .verify(&headers, &target, issued_at + 61, Scope::ClusterReplicate)
            .test_unwrap_err(),
        PeerAuthError::Stale
    );
    assert_eq!(
        access
            .peers
            .verify(
                &headers,
                &target,
                issued_at,
                Scope::ClusterOpeningsReplicate
            )
            .test_unwrap_err(),
        PeerAuthError::MissingScope(Scope::ClusterOpeningsReplicate)
    );
}

#[test]
fn peer_signature_from_unpinned_key_refused() {
    let pinned = Keypair::generate();
    let impostor = Keypair::generate();
    let node = "https://node-b.example:9101";
    let access = TrustAccessConfig::from_toml_str(&config(&format!(
        "{}{}",
        reader(),
        peer(node, &pinned, &["cluster:replicate"])
    )))
    .test_unwrap();
    let target = PeerRequestTarget {
        method: "GET",
        path: "/v1/internal/cluster/status",
        query: "",
    };
    let issued_at = 1_792_234_800;
    let forged = signed_peer_headers(&impostor, node, &target, issued_at, None);
    assert_eq!(
        access
            .peers
            .verify(&forged, &target, issued_at, Scope::ClusterReplicate)
            .test_unwrap_err(),
        PeerAuthError::BadSignature
    );
    let unknown_node = signed_peer_headers(
        &impostor,
        "https://node-x.example:9101",
        &target,
        issued_at,
        None,
    );
    assert_eq!(
        access
            .peers
            .verify(&unknown_node, &target, issued_at, Scope::ClusterReplicate)
            .test_unwrap_err(),
        PeerAuthError::UnpinnedNode
    );
}

pub(crate) fn signed_peer_headers(
    keypair: &Keypair,
    node_id: &str,
    target: &PeerRequestTarget<'_>,
    issued_at: i64,
    term: Option<u64>,
) -> HeaderMap {
    let signature =
        sign_cluster_peer_request(keypair, node_id, target, issued_at, term).test_unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        CLUSTER_NODE_ID_HEADER,
        HeaderValue::from_str(node_id).test_unwrap(),
    );
    headers.insert(
        CLUSTER_AUTH_ISSUED_AT_HEADER,
        HeaderValue::from_str(&issued_at.to_string()).test_unwrap(),
    );
    headers.insert(
        CLUSTER_AUTH_SIGNATURE_HEADER,
        HeaderValue::from_str(&signature).test_unwrap(),
    );
    if let Some(term) = term {
        headers.insert(
            CLUSTER_AUTH_TERM_HEADER,
            HeaderValue::from_str(&term.to_string()).test_unwrap(),
        );
    }
    headers
}
