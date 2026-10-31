use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use chio_core::crypto::Keypair;
use chio_store_sqlite::{ClusterPeerReplayStoreError, SqliteClusterPeerReplayStore};
use chio_test_support::prelude::*;
use sha2::{Digest, Sha256};

use super::caller::parse_secret_digest;
use super::peer::{peer_signature_payload, SignedPeerFields};
use super::*;
use crate::trust_control::report_validation::normalize_cluster_url;
use crate::trust_control::{
    CLUSTER_AUTH_ISSUED_AT_HEADER, CLUSTER_AUTH_SIGNATURE_HEADER, CLUSTER_AUTH_TERM_HEADER,
    CLUSTER_NODE_ID_HEADER,
};

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

pub(crate) const SELF_NODE: &str = "https://node-a.example:9101";

/// The scopes every pinned replica needs: the delta lanes and the initial
/// cluster snapshot.
pub(crate) const REPLICA_SCOPES: &[&str] = &["cluster:replicate", "cluster-openings:replicate"];

/// Remove `scope` from a loaded peer pin. Load refuses such a peer set, so this
/// is how route and handler tests reach their per-route scope refusals.
pub(crate) fn withhold_peer_scope(pins: &mut ClusterPeerPins, node_id: &str, scope: Scope) {
    let removed = pins
        .peers
        .get_mut(node_id)
        .is_some_and(|peer| peer.scopes.remove(&scope));
    assert!(removed, "peer {node_id} holds no {scope} to withhold");
}

pub(crate) fn config(body: &str) -> String {
    let cluster = if body.contains("[[cluster.peers]]") {
        format!(
            "[cluster]\nnode_id = \"{SELF_NODE}\"\nnode_key_file = \"/nonexistent/node-a.seed\"\n"
        )
    } else {
        String::new()
    };
    format!("deployment = \"{DEPLOYMENT}\"\ninternal_listen = \"127.0.0.1:9101\"\n{cluster}{body}")
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

/// Decode an access configuration TOML document and validate it.
pub(crate) fn parse(text: &str) -> Result<TrustAccessConfig, TrustAccessError> {
    TrustAccessConfig::from_document(toml::from_str(text).test_unwrap())
}

fn decode_refused(text: &str) -> bool {
    toml::from_str::<AccessConfigDocument>(text).is_err()
}

fn refusal(text: &str) -> TrustAccessError {
    parse(text).test_unwrap_err()
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
    assert_eq!(Scope::ALL.len(), 41);
    assert_eq!(
        Scope::parse("root-exchange:sign"),
        Some(Scope::RootExchangeSign)
    );
    assert!(!Scope::RootExchangeSign.is_cluster());
    for scope in Scope::ALL {
        assert_eq!(Scope::parse(scope.as_str()), Some(*scope));
    }
    assert_eq!(Scope::parse("receipts:write"), None);
    assert_eq!(Scope::parse("RECEIPTS:READ"), None);
}

#[test]
fn old_config_keys_refuse_at_startup() {
    for key in [
        "service_token = \"t\"",
        "tenant_read_tokens = { tenant-a = \"t\" }",
    ] {
        assert!(decode_refused(&config(&format!("{key}\n{}", reader()))));
    }
}

#[test]
fn tenant_authority_decodes_only_its_two_forms() {
    let deployment = "tenant_authority = \"deployment\"\n";
    assert!(reader().contains(deployment));
    for value in [
        "{ deployment = {} }",
        "{ tenant = \"a\", x = 1 }",
        "{ tenant = 1 }",
        "{}",
        "\"Deployment\"",
        "\"tenant\"",
        "1",
    ] {
        let text = reader().replace(deployment, &format!("tenant_authority = {value}\n"));
        assert!(decode_refused(&config(&text)), "{value}");
    }
    let tenant = reader().replace(deployment, "tenant_authority = { tenant = \"a\" }\n");
    assert!(!decode_refused(&config(&tenant)));
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
    for text in [
        reader().replace("\"deployment\"\n", "\"tenant\"\n"),
        reader().replace("kind = \"caller\"", "kind = \"admin\""),
        format!("{}extra = 1\n", reader()),
    ] {
        assert!(decode_refused(&config(&text)), "{text}");
    }
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
    assert_eq!(
        refusal(&with_peer(peer(node, &keypair, &["cluster:replicate"]))),
        TrustAccessError::PeerSnapshotScopeMissing(node.to_string())
    );
    let replica = parse(&with_peer(peer(node, &keypair, REPLICA_SCOPES))).test_unwrap();
    assert_eq!(
        replica
            .peers()
            .iter()
            .map(|pin| pin.scopes.iter().copied().collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        vec![vec![
            Scope::ClusterReplicate,
            Scope::ClusterOpeningsReplicate
        ]]
    );
    assert_eq!(
        refusal(&with_peer(peer(
            node,
            &keypair,
            &["cluster:replicate", "cluster:replicate"]
        ))),
        TrustAccessError::DuplicatePeerScope {
            node_id: node.to_string(),
            scope: Scope::ClusterReplicate,
        }
    );
    let twice = format!(
        "{}{}",
        peer(node, &keypair, REPLICA_SCOPES),
        peer(node, &Keypair::generate(), REPLICA_SCOPES)
    );
    assert_eq!(
        refusal(&with_peer(twice)),
        TrustAccessError::DuplicatePeer(node.to_string())
    );
    let shared_key = format!(
        "{}{}",
        peer(node, &keypair, REPLICA_SCOPES),
        peer("https://node-c.example:9101", &keypair, REPLICA_SCOPES)
    );
    assert_eq!(
        refusal(&with_peer(shared_key)),
        TrustAccessError::DuplicatePeerKey(
            node.to_string(),
            "https://node-c.example:9101".to_string()
        )
    );
    let bad_key =
        peer(node, &keypair, REPLICA_SCOPES).replace(&keypair.public_key().to_hex(), "zz");
    assert_eq!(
        refusal(&with_peer(bad_key)),
        TrustAccessError::InvalidPeerKey(node.to_string())
    );
}

#[test]
fn internal_listener_must_not_share_the_public_address() {
    let access = parse(&config(&reader())).test_unwrap();
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
    let access = parse(&config(&reader())).test_unwrap();
    let caller = access
        .credentials()
        .validate_caller(&bearer("reader-secret"), Scope::ReceiptsRead)
        .test_unwrap();
    assert_eq!(caller.credential_id, "reader");
    assert_eq!(caller.deployment, DEPLOYMENT);
    assert_eq!(caller.tenant_authority, TenantAuthority::Deployment);
    assert_eq!(
        access
            .credentials()
            .validate_caller(&bearer("reader-secret"), Scope::ReportsRead)
            .test_unwrap_err(),
        CallerAuthError::MissingScope(Scope::ReportsRead)
    );
    assert_eq!(
        access
            .credentials()
            .validate_caller(&bearer("other-secret"), Scope::ReceiptsRead)
            .test_unwrap_err(),
        CallerAuthError::Unauthenticated
    );
    assert_eq!(
        access
            .credentials()
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
            .credentials()
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
    let access = parse(&text).test_unwrap();
    let caller = access
        .credentials()
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

fn peer_access(node: &str, keypair: &Keypair, scopes: &[&str]) -> TrustAccessConfig {
    parse(&config(&format!(
        "{}{}",
        reader(),
        peer(node, keypair, scopes)
    )))
    .test_unwrap()
}

fn verify(
    access: &TrustAccessConfig,
    headers: &HeaderMap,
    target: &PeerRequestTarget<'_>,
    now: i64,
    nonces: &PeerNonceCache,
) -> Result<AuthenticatedPeer, PeerAuthError> {
    access
        .peers()
        .verify(headers, target, now, Scope::ClusterReplicate, nonces)
}

const ISSUED_AT: i64 = 1_792_234_800;
const NODE_B: &str = "https://node-b.example:9101";
const NODE_C: &str = "https://node-c.example:9101";

/// A fresh cluster peer replay database path, in a directory that lives as
/// long as the test process.
pub(crate) fn test_peer_replay_db_path() -> std::path::PathBuf {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    DIR.get_or_init(|| tempfile::tempdir().test_unwrap())
        .path()
        .join(format!("cluster-peer-replay-{index}.sqlite3"))
}

/// A fresh, empty cluster peer replay store.
pub(crate) fn test_peer_replay_store() -> Arc<SqliteClusterPeerReplayStore> {
    Arc::new(SqliteClusterPeerReplayStore::open(test_peer_replay_db_path()).test_unwrap())
}

/// A peer nonce cache on `store` that started at `start_secs`.
pub(crate) fn test_nonce_cache(
    store: &Arc<SqliteClusterPeerReplayStore>,
    start_secs: Option<i64>,
    pinned_peers: usize,
) -> PeerNonceCache {
    PeerNonceCache::open(Arc::clone(store), start_secs, pinned_peers).test_unwrap()
}

fn nonce_cache() -> PeerNonceCache {
    nonce_cache_on(&test_peer_replay_store())
}

fn nonce_cache_on(store: &Arc<SqliteClusterPeerReplayStore>) -> PeerNonceCache {
    test_nonce_cache(
        store,
        Some(ISSUED_AT - CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS),
        1,
    )
}

fn status_target() -> PeerRequestTarget<'static> {
    PeerRequestTarget {
        method: "GET",
        path: "/v1/internal/cluster/status",
        query: "",
        body: b"",
    }
}

fn partition_target() -> PeerRequestTarget<'static> {
    PeerRequestTarget {
        method: "POST",
        path: "/v1/internal/cluster/partition",
        query: "",
        body: br#"{"blocked":[]}"#,
    }
}

#[test]
fn peer_signature_binds_node_path_query_body_and_time() {
    let keypair = Keypair::generate();
    let mut access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    withhold_peer_scope(access.peers_mut(), NODE_B, Scope::ClusterOpeningsReplicate);
    let target = PeerRequestTarget {
        method: "GET",
        path: "/v1/internal/revocations/delta",
        query: "afterSeq=7",
        body: b"",
    };
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, Some(3));
    let peer = verify(&access, &headers, &target, ISSUED_AT, &nonce_cache()).test_unwrap();
    assert_eq!(peer.node_id, NODE_B);
    assert_eq!(peer.term, Some(3));
    for (changed, expected) in [
        (
            PeerRequestTarget {
                path: "/v1/internal/budgets/delta",
                ..target
            },
            PeerAuthError::BadSignature,
        ),
        (
            PeerRequestTarget {
                query: "afterSeq=0",
                ..target
            },
            PeerAuthError::BadSignature,
        ),
        (
            PeerRequestTarget {
                method: "POST",
                ..target
            },
            PeerAuthError::BadSignature,
        ),
        (
            PeerRequestTarget {
                body: b"{}",
                ..target
            },
            PeerAuthError::BodyMismatch,
        ),
    ] {
        assert_eq!(
            verify(&access, &headers, &changed, ISSUED_AT, &nonce_cache()).test_unwrap_err(),
            expected
        );
    }
    assert_eq!(
        verify(&access, &headers, &target, ISSUED_AT + 61, &nonce_cache()).test_unwrap_err(),
        PeerAuthError::Stale
    );
    assert_eq!(
        access
            .peers()
            .verify(
                &headers,
                &target,
                ISSUED_AT,
                Scope::ClusterOpeningsReplicate,
                &nonce_cache(),
            )
            .test_unwrap_err(),
        PeerAuthError::MissingScope(Scope::ClusterOpeningsReplicate)
    );
}

#[test]
fn peer_body_digest_mismatch_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let signed = PeerRequestTarget {
        method: "POST",
        path: "/v1/internal/cluster/partition",
        query: "",
        body: br#"{"blocked":["https://node-c.example:9101"]}"#,
    };
    let headers = signed_peer_headers(&keypair, NODE_B, &signed, ISSUED_AT, Some(2));
    let swapped = PeerRequestTarget {
        body: br#"{"blocked":[]}"#,
        ..signed
    };
    let error = verify(&access, &headers, &swapped, ISSUED_AT, &nonce_cache()).test_unwrap_err();
    assert_eq!(error, PeerAuthError::BodyMismatch);
    assert_eq!(
        error.to_string(),
        "cluster peer request body does not match its signed digest"
    );
    verify(&access, &headers, &signed, ISSUED_AT, &nonce_cache()).test_unwrap();
}

#[test]
fn peer_nonce_replay_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let nonces = nonce_cache();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    verify(&access, &headers, &target, ISSUED_AT, &nonces).test_unwrap();
    let error = verify(&access, &headers, &target, ISSUED_AT + 59, &nonces).test_unwrap_err();
    assert_eq!(error, PeerAuthError::ReplayedNonce);
    assert_eq!(error.to_string(), "cluster peer nonce was already used");
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    let fresh = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    verify(&access, &fresh, &target, ISSUED_AT + 1, &nonces).test_unwrap();
}

#[test]
fn peer_nonce_cache_refuses_when_full() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let nonces = nonce_cache();
    for index in 0..CLUSTER_PEER_NONCE_CACHE_CAPACITY {
        nonces
            .record(NODE_B, &format!("{index:064x}"), ISSUED_AT, ISSUED_AT)
            .test_unwrap();
    }
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    let full = verify(&access, &headers, &target, ISSUED_AT, &nonces).test_unwrap_err();
    assert_eq!(full, PeerAuthError::ReplayCacheUnavailable);
    assert_eq!(
        full.to_string(),
        "cluster peer replay cache cannot admit another request"
    );
    assert_eq!(full.status(), StatusCode::SERVICE_UNAVAILABLE);
    let after_window = ISSUED_AT + CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS + 1;
    let later = signed_peer_headers(&keypair, NODE_B, &target, after_window, None);
    verify(&access, &later, &target, after_window, &nonces).test_unwrap();
}

#[test]
fn peer_headers_must_carry_nonce_and_body_digest() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    for header in [CLUSTER_AUTH_NONCE_HEADER, CLUSTER_AUTH_BODY_SHA256_HEADER] {
        let mut missing = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
        missing.remove(header);
        let mut uppercase = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
        let value = uppercase
            .get(header)
            .and_then(|value| value.to_str().ok())
            .test_unwrap()
            .to_ascii_uppercase();
        uppercase.insert(header, HeaderValue::from_str(&value).test_unwrap());
        for headers in [missing, uppercase] {
            assert_eq!(
                verify(&access, &headers, &target, ISSUED_AT, &nonce_cache()).test_unwrap_err(),
                PeerAuthError::Unauthenticated,
                "{header}"
            );
        }
    }
}

#[test]
fn peer_signature_from_unpinned_key_refused() {
    let pinned = Keypair::generate();
    let impostor = Keypair::generate();
    let access = peer_access(NODE_B, &pinned, REPLICA_SCOPES);
    let target = status_target();
    let forged = signed_peer_headers(&impostor, NODE_B, &target, ISSUED_AT, None);
    let wrong_key = verify(&access, &forged, &target, ISSUED_AT, &nonce_cache()).test_unwrap_err();
    assert_eq!(wrong_key, PeerAuthError::BadSignature);
    let unknown_node = signed_peer_headers(
        &impostor,
        "https://node-x.example:9101",
        &target,
        ISSUED_AT,
        None,
    );
    let unpinned =
        verify(&access, &unknown_node, &target, ISSUED_AT, &nonce_cache()).test_unwrap_err();
    assert_eq!(unpinned, wrong_key);
    assert_eq!(unpinned.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn credential_debug_redacts_secret_digests() {
    let access = parse(&config(&reader())).test_unwrap();
    let rendered = format!("{access:?}");
    assert!(rendered.contains("[REDACTED]"), "{rendered}");
    assert!(!rendered.contains(&digest("reader-secret")), "{rendered}");
    let bytes = parse_secret_digest("reader", &digest("reader-secret")).test_unwrap();
    assert!(!rendered.contains(&format!("{bytes:?}")), "{rendered}");
}

static NONCE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(crate) fn fresh_nonce() -> [u8; 32] {
    let mut nonce = [0x5a_u8; 32];
    let counter = NONCE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    nonce[..8].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub(crate) fn signed_peer_headers(
    keypair: &Keypair,
    node_id: &str,
    target: &PeerRequestTarget<'_>,
    issued_at: i64,
    term: Option<u64>,
) -> HeaderMap {
    signed_peer_headers_for(keypair, node_id, SELF_NODE, target, issued_at, term)
}

pub(crate) fn signed_peer_headers_for(
    keypair: &Keypair,
    node_id: &str,
    recipient: &str,
    target: &PeerRequestTarget<'_>,
    issued_at: i64,
    term: Option<u64>,
) -> HeaderMap {
    let addressing = PeerAddressing {
        deployment: DEPLOYMENT,
        sender: node_id,
        recipient,
    };
    let signed = sign_cluster_peer_request(
        keypair,
        &addressing,
        target,
        &fresh_nonce(),
        issued_at,
        term,
    )
    .test_unwrap();
    let mut headers = HeaderMap::new();
    for (name, value) in [
        (CLUSTER_NODE_ID_HEADER, node_id.to_string()),
        (CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string()),
        (CLUSTER_AUTH_SIGNATURE_HEADER, signed.signature),
        (CLUSTER_AUTH_NONCE_HEADER, signed.nonce),
        (CLUSTER_AUTH_BODY_SHA256_HEADER, signed.body_sha256),
    ] {
        headers.insert(name, HeaderValue::from_str(&value).test_unwrap());
    }
    if let Some(term) = term {
        headers.insert(
            CLUSTER_AUTH_TERM_HEADER,
            HeaderValue::from_str(&term.to_string()).test_unwrap(),
        );
    }
    headers
}

#[test]
fn peer_request_for_another_receiver_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = partition_target();
    let for_node_c = signed_peer_headers_for(
        &keypair,
        NODE_B,
        "https://node-c.example:9101",
        &target,
        ISSUED_AT,
        Some(2),
    );
    let refused =
        verify(&access, &for_node_c, &target, ISSUED_AT, &nonce_cache()).test_unwrap_err();
    assert_eq!(refused, PeerAuthError::BadSignature);
    assert_eq!(
        refused.to_string(),
        "cluster peer signature does not verify under a pinned key"
    );
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let for_this_node =
        signed_peer_headers_for(&keypair, NODE_B, SELF_NODE, &target, ISSUED_AT, Some(2));
    verify(&access, &for_this_node, &target, ISSUED_AT, &nonce_cache()).test_unwrap();
}

#[test]
fn peer_request_for_another_deployment_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = partition_target();
    let other_deployment = sign_cluster_peer_request(
        &keypair,
        &PeerAddressing {
            deployment: "dep-b",
            sender: NODE_B,
            recipient: SELF_NODE,
        },
        &target,
        &fresh_nonce(),
        ISSUED_AT,
        Some(2),
    )
    .test_unwrap();
    let mut headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, Some(2));
    verify(&access, &headers, &target, ISSUED_AT, &nonce_cache()).test_unwrap();
    for (name, value) in [
        (CLUSTER_AUTH_SIGNATURE_HEADER, other_deployment.signature),
        (CLUSTER_AUTH_NONCE_HEADER, other_deployment.nonce),
    ] {
        headers.insert(name, HeaderValue::from_str(&value).test_unwrap());
    }
    let refused = verify(&access, &headers, &target, ISSUED_AT, &nonce_cache()).test_unwrap_err();
    assert_eq!(refused, PeerAuthError::BadSignature);
    assert_eq!(
        refused.to_string(),
        "cluster peer signature does not verify under a pinned key"
    );
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn cluster_identity_rules_refuse_at_startup() {
    let keypair = Keypair::generate();
    let peers_without_identity = format!(
        "deployment = \"{DEPLOYMENT}\"\ninternal_listen = \"127.0.0.1:9101\"\n{}{}",
        reader(),
        peer(NODE_B, &keypair, REPLICA_SCOPES)
    );
    assert_eq!(
        refusal(&peers_without_identity),
        TrustAccessError::ClusterIdentityRequired
    );
    let identity_without_peers = format!(
        "deployment = \"{DEPLOYMENT}\"\ninternal_listen = \"127.0.0.1:9101\"\n[cluster]\nnode_id = \"{SELF_NODE}\"\nnode_key_file = \"/k\"\n{}",
        reader()
    );
    assert_eq!(
        refusal(&identity_without_peers),
        TrustAccessError::ClusterIdentityWithoutPeers
    );
    assert_eq!(
        refusal(&config(&format!(
            "{}{}",
            reader(),
            peer(SELF_NODE, &keypair, REPLICA_SCOPES)
        ))),
        TrustAccessError::SelfPinned(SELF_NODE.to_string())
    );
    let invalid_node_id = refusal(
        &config(&format!(
            "{}{}",
            reader(),
            peer(NODE_B, &keypair, REPLICA_SCOPES)
        ))
        .replace(&format!("node_id = \"{SELF_NODE}\""), "node_id = \"  /\""),
    );
    assert_eq!(
        invalid_node_id,
        TrustAccessError::InvalidClusterNodeId("  /".to_string())
    );
    assert_eq!(
        invalid_node_id.to_string(),
        "[cluster] node_id \"  /\" is invalid"
    );
}

/// Deterministic test node key for `node_id`, so every test node pins the same
/// key for a peer.
pub(crate) fn test_node_keypair(node_id: &str) -> Keypair {
    let normalized = normalize_cluster_url(node_id).test_unwrap();
    let seed: [u8; 32] = Sha256::digest(format!("chio-test-node:{normalized}").as_bytes()).into();
    Keypair::from_seed(&seed)
}

/// Every non-cluster scope, for a test credential standing in for a full
/// deployment client.
pub(crate) fn all_caller_scopes() -> Vec<&'static str> {
    Scope::ALL
        .iter()
        .filter(|scope| !scope.is_cluster())
        .map(|scope| scope.as_str())
        .collect()
}

/// Access for a single test node: one deployment credential for `secret`
/// holding every caller scope.
pub(crate) fn test_access(secret: &str) -> std::sync::Arc<TrustAccess> {
    test_access_with_cluster(secret, &[], None, &[])
}

/// Access for a test node: a full deployment credential for `secret`, one
/// `Tenant(t)` read credential per `(tenant, secret)` pair, and when
/// `self_node` is set, a cluster identity pinning each of `peers` (with
/// `internal_url` equal to the peer node id).
pub(crate) fn test_access_with_cluster(
    secret: &str,
    tenant_readers: &[(&str, &str)],
    self_node: Option<&str>,
    peers: &[&str],
) -> std::sync::Arc<TrustAccess> {
    let mut body = credential(
        "test-deployment-client",
        "deployment",
        secret,
        &all_caller_scopes(),
        None,
    );
    for (index, (tenant, tenant_secret)) in tenant_readers.iter().enumerate() {
        body.push_str(&credential(
            &format!("test-tenant-reader-{index}"),
            "caller",
            tenant_secret,
            &["receipts:read", "reports:read", "evidence:read"],
            Some(tenant),
        ));
    }
    let node_keypair = match self_node {
        Some(self_node) if !peers.is_empty() => {
            body.push_str(&format!(
                "[cluster]\nnode_id = \"{self_node}\"\nnode_key_file = \"/test/node.seed\"\n"
            ));
            for peer_url in peers {
                body.push_str(&peer(
                    peer_url,
                    &test_node_keypair(peer_url),
                    &["cluster:replicate", "cluster-openings:replicate"],
                ));
            }
            Some(test_node_keypair(self_node))
        }
        _ => None,
    };
    let text = format!("deployment = \"{DEPLOYMENT}\"\ninternal_listen = \"127.0.0.1:0\"\n{body}");
    let config = parse(&text).test_unwrap();
    std::sync::Arc::new(TrustAccess::from_parts(config, node_keypair).test_unwrap())
}

/// Access with one deployment credential for `secret` holding only `scopes`.
pub(crate) fn test_access_with_scopes(
    secret: &str,
    scopes: &[&str],
) -> std::sync::Arc<TrustAccess> {
    let text = format!(
        "deployment = \"{DEPLOYMENT}\"\ninternal_listen = \"127.0.0.1:0\"\n{}",
        credential("test-limited-client", "deployment", secret, scopes, None)
    );
    let config = parse(&text).test_unwrap();
    std::sync::Arc::new(TrustAccess::from_parts(config, None).test_unwrap())
}

/// Make `config` a clustered test node at `self_node` pinning `peers`, with
/// the same full deployment credential for `"token"`.
pub(crate) fn set_test_peers(
    config: &mut super::super::TrustServiceConfig,
    self_node: &str,
    peers: &[&str],
) {
    set_test_peers_with_secret(config, "token", self_node, peers);
}

/// As `set_test_peers`, with the full deployment credential for `secret`.
pub(crate) fn set_test_peers_with_secret(
    config: &mut super::super::TrustServiceConfig,
    secret: &str,
    self_node: &str,
    peers: &[&str],
) {
    let self_id = normalize_cluster_url(self_node).test_unwrap();
    let peers: Vec<&str> = peers
        .iter()
        .copied()
        .filter(|peer| normalize_cluster_url(peer).test_unwrap() != self_id)
        .collect();
    config.advertise_url = Some(self_node.to_string());
    config.access = test_access_with_cluster(secret, &[], Some(self_node), &peers);
    config.cluster_peer_replay_db_path = Some(test_peer_replay_db_path());
}

/// Scopes of the authority workload credential tests stand up beside the
/// full client: authority status and capability issuance only.
pub(crate) const WORKLOAD_SCOPES: &[&str] = &["authority:read", "capabilities:issue"];

/// Scopes a migrated tenant read credential holds.
pub(crate) const TENANT_READ_SCOPES: &[&str] = &["receipts:read", "reports:read", "evidence:read"];

/// Access with the full deployment credential for `secret`, an optional
/// authority workload credential, and one tenant read credential per
/// `(tenant, secret)`.
pub(crate) fn test_access_with_roles(
    secret: &str,
    workload_secret: Option<&str>,
    tenant_readers: &[(&str, &str)],
) -> std::sync::Arc<TrustAccess> {
    let mut body = credential(
        "test-deployment-client",
        "deployment",
        secret,
        &all_caller_scopes(),
        None,
    );
    if let Some(workload_secret) = workload_secret {
        body.push_str(&credential(
            "test-authority-workload",
            "deployment",
            workload_secret,
            WORKLOAD_SCOPES,
            None,
        ));
    }
    for (index, (tenant, tenant_secret)) in tenant_readers.iter().enumerate() {
        body.push_str(&credential(
            &format!("test-tenant-reader-{index}"),
            "caller",
            tenant_secret,
            TENANT_READ_SCOPES,
            Some(tenant),
        ));
    }
    let text = format!("deployment = \"{DEPLOYMENT}\"\ninternal_listen = \"127.0.0.1:0\"\n{body}");
    let config = parse(&text).test_unwrap();
    std::sync::Arc::new(TrustAccess::from_parts(config, None).test_unwrap())
}

#[test]
fn peer_replay_after_restart_on_a_reset_store_keeps_the_start_plus_lead_floor() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    verify(&access, &headers, &target, ISSUED_AT, &nonce_cache()).test_unwrap();
    let reset = test_peer_replay_store();
    let restarted = test_nonce_cache(&reset, Some(ISSUED_AT + 3), 1);
    let error = verify(&access, &headers, &target, ISSUED_AT + 5, &restarted).test_unwrap_err();
    assert_eq!(error, PeerAuthError::Stale);
    assert_eq!(
        error.to_string(),
        "cluster peer signature is outside the freshness window"
    );
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    let started_without_clock = test_nonce_cache(&test_peer_replay_store(), None, 1);
    assert_eq!(
        verify(
            &access,
            &headers,
            &target,
            ISSUED_AT + 5,
            &started_without_clock
        )
        .test_unwrap_err(),
        PeerAuthError::Stale
    );
    let first_fresh = ISSUED_AT + 3 + CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS + 1;
    let in_lead = signed_peer_headers(&keypair, NODE_B, &target, first_fresh - 1, None);
    assert_eq!(
        verify(&access, &in_lead, &target, first_fresh, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
    let fresh = signed_peer_headers(&keypair, NODE_B, &target, first_fresh, None);
    verify(&access, &fresh, &target, first_fresh, &restarted).test_unwrap();
}

#[test]
fn peer_replay_in_the_restart_second_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    let store = test_peer_replay_store();
    let before_restart = nonce_cache_on(&store);
    verify(&access, &headers, &target, ISSUED_AT, &before_restart).test_unwrap();
    let restarted = test_nonce_cache(&store, Some(ISSUED_AT), 1);
    assert_eq!(
        verify(&access, &headers, &target, ISSUED_AT, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
}

#[test]
fn peer_future_dated_replay_after_restart_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let store = test_peer_replay_store();
    let before_restart = nonce_cache_on(&store);
    let led = signed_peer_headers(
        &keypair,
        NODE_B,
        &target,
        ISSUED_AT + CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS,
        None,
    );
    verify(&access, &led, &target, ISSUED_AT, &before_restart).test_unwrap();
    let restarted = test_nonce_cache(&store, Some(ISSUED_AT + 1), 1);
    assert_eq!(
        verify(&access, &led, &target, ISSUED_AT + 1, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
    let far_ahead = signed_peer_headers(
        &keypair,
        NODE_B,
        &target,
        ISSUED_AT + CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS + 1,
        None,
    );
    assert_eq!(
        verify(&access, &far_ahead, &target, ISSUED_AT, &before_restart).test_unwrap_err(),
        PeerAuthError::Stale
    );
}

#[test]
fn peer_replay_after_restart_with_clock_moved_back_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let store = test_peer_replay_store();
    let before_restart = nonce_cache_on(&store);
    let older = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT - 10, None);
    let latest = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    for (headers, now) in [(&older, ISSUED_AT - 10), (&latest, ISSUED_AT)] {
        verify(&access, headers, &target, now, &before_restart).test_unwrap();
    }
    let restarted = test_nonce_cache(&store, Some(ISSUED_AT - 20), 1);
    for headers in [&latest, &older] {
        assert_eq!(
            verify(&access, headers, &target, ISSUED_AT - 3, &restarted).test_unwrap_err(),
            PeerAuthError::Stale
        );
    }
}

fn two_peer_access(node_b: &Keypair, node_c: &Keypair) -> TrustAccessConfig {
    parse(&config(&format!(
        "{}{}{}",
        reader(),
        peer(NODE_B, node_b, REPLICA_SCOPES),
        peer(NODE_C, node_c, REPLICA_SCOPES)
    )))
    .test_unwrap()
}

#[test]
fn peer_without_a_stored_mark_after_restart_gets_the_start_plus_lead_floor() {
    let node_b = Keypair::generate();
    let node_c = Keypair::generate();
    let access = two_peer_access(&node_b, &node_c);
    let target = status_target();
    let store = test_peer_replay_store();
    let before_restart = test_nonce_cache(
        &store,
        Some(ISSUED_AT - CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS),
        2,
    );
    let from_b = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT, None);
    verify(&access, &from_b, &target, ISSUED_AT, &before_restart).test_unwrap();
    let start = ISSUED_AT - 20;
    let restarted = test_nonce_cache(&store, Some(start), 2);
    let at_floor = start + CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS;
    let now = start + 10;
    let c_at_floor = signed_peer_headers(&node_c, NODE_C, &target, at_floor, None);
    assert_eq!(
        verify(&access, &c_at_floor, &target, now, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
    let c_above_floor = signed_peer_headers(&node_c, NODE_C, &target, at_floor + 1, None);
    verify(&access, &c_above_floor, &target, now, &restarted).test_unwrap();
    let b_above_start_floor = signed_peer_headers(&node_b, NODE_B, &target, at_floor + 1, None);
    assert_eq!(
        verify(&access, &b_above_start_floor, &target, now, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
    assert_eq!(
        store.high_waters().test_unwrap(),
        std::collections::BTreeMap::from([
            (NODE_B.to_string(), ISSUED_AT),
            (NODE_C.to_string(), at_floor + 1),
        ])
    );
}

#[test]
fn peer_high_water_marks_are_independent_per_peer() {
    let node_b = Keypair::generate();
    let node_c = Keypair::generate();
    let access = two_peer_access(&node_b, &node_c);
    let target = status_target();
    let store = test_peer_replay_store();
    let before_restart = test_nonce_cache(
        &store,
        Some(ISSUED_AT - CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS),
        2,
    );
    let b_late = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT + 3, None);
    verify(&access, &b_late, &target, ISSUED_AT, &before_restart).test_unwrap();
    let c_early = signed_peer_headers(&node_c, NODE_C, &target, ISSUED_AT, None);
    verify(&access, &c_early, &target, ISSUED_AT, &before_restart).test_unwrap();
    let restarted = test_nonce_cache(&store, Some(ISSUED_AT - 30), 2);
    let c_next = signed_peer_headers(&node_c, NODE_C, &target, ISSUED_AT + 1, None);
    verify(&access, &c_next, &target, ISSUED_AT, &restarted).test_unwrap();
    let b_same_second = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT + 3, None);
    assert_eq!(
        verify(&access, &b_same_second, &target, ISSUED_AT, &restarted).test_unwrap_err(),
        PeerAuthError::Stale
    );
    let b_next = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT + 4, None);
    verify(&access, &b_next, &target, ISSUED_AT, &restarted).test_unwrap();
}

#[test]
fn peer_requests_in_one_second_share_one_durable_mark() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let store = test_peer_replay_store();
    let nonces = nonce_cache_on(&store);
    for _ in 0..3 {
        let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
        verify(&access, &headers, &target, ISSUED_AT, &nonces).test_unwrap();
    }
    let earlier = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT - 1, None);
    verify(&access, &earlier, &target, ISSUED_AT, &nonces).test_unwrap();
    assert_eq!(
        store.high_waters().test_unwrap(),
        std::collections::BTreeMap::from([(NODE_B.to_string(), ISSUED_AT)])
    );
}

#[test]
fn peer_replay_store_fault_refuses_with_503() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let path = test_peer_replay_db_path();
    let store = Arc::new(SqliteClusterPeerReplayStore::open(&path).test_unwrap());
    let nonces = nonce_cache_on(&store);
    rusqlite::Connection::open(&path)
        .test_unwrap()
        .execute_batch("DROP TABLE cluster_peer_replay_high_water;")
        .test_unwrap();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    let error = verify(&access, &headers, &target, ISSUED_AT, &nonces).test_unwrap_err();
    assert_eq!(error, PeerAuthError::PeerReplayStoreUnavailable);
    assert_eq!(
        error.to_string(),
        "cluster peer replay high-water store is unavailable"
    );
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        verify(&access, &headers, &target, ISSUED_AT, &nonces).test_unwrap_err(),
        PeerAuthError::PeerReplayStoreUnavailable
    );
    assert!(matches!(
        PeerNonceCache::open(Arc::clone(&store), Some(ISSUED_AT), 1).test_unwrap_err(),
        ClusterPeerReplayStoreError::Sqlite(_)
    ));
}

#[test]
fn concurrent_duplicate_peer_requests_accept_exactly_once() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let nonces = nonce_cache();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    let outcomes: Vec<Result<AuthenticatedPeer, PeerAuthError>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| verify(&access, &headers, &target, ISSUED_AT, &nonces)))
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().test_unwrap())
            .collect()
    });
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    for refused in outcomes.iter().filter_map(|outcome| outcome.as_ref().err()) {
        assert_eq!(*refused, PeerAuthError::ReplayedNonce);
    }
}

#[test]
fn peer_replay_after_clock_step_back_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let nonces = nonce_cache();
    let first = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    verify(&access, &first, &target, ISSUED_AT, &nonces).test_unwrap();
    let later = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT + 200, None);
    verify(&access, &later, &target, ISSUED_AT + 200, &nonces).test_unwrap();
    let error = verify(&access, &first, &target, ISSUED_AT + 5, &nonces).test_unwrap_err();
    assert_eq!(error, PeerAuthError::Stale);
    assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    let behind = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT + 5, None);
    assert_eq!(
        verify(&access, &behind, &target, ISSUED_AT + 5, &nonces).test_unwrap_err(),
        PeerAuthError::Stale
    );
    let current = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT + 200, None);
    verify(&access, &current, &target, ISSUED_AT + 5, &nonces).test_unwrap();
}

#[test]
fn peer_replay_at_the_window_boundary_refuses() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let nonces = nonce_cache();
    let headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    verify(&access, &headers, &target, ISSUED_AT, &nonces).test_unwrap();
    let at_boundary = ISSUED_AT + CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS;
    assert_eq!(
        verify(&access, &headers, &target, at_boundary, &nonces).test_unwrap_err(),
        PeerAuthError::ReplayedNonce
    );
    assert_eq!(
        verify(&access, &headers, &target, at_boundary + 1, &nonces).test_unwrap_err(),
        PeerAuthError::Stale
    );
}

#[test]
fn peer_nonce_quota_keeps_other_peers_admitted() {
    let node_b = Keypair::generate();
    let node_c = Keypair::generate();
    let access = parse(&config(&format!(
        "{}{}{}",
        reader(),
        peer(NODE_B, &node_b, REPLICA_SCOPES),
        peer(NODE_C, &node_c, REPLICA_SCOPES)
    )))
    .test_unwrap();
    let target = status_target();
    let nonces = test_nonce_cache(
        &test_peer_replay_store(),
        Some(ISSUED_AT - CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS),
        2,
    );
    for index in 0..CLUSTER_PEER_NONCE_CACHE_CAPACITY / 2 {
        nonces
            .record(NODE_B, &format!("{index:064x}"), ISSUED_AT, ISSUED_AT)
            .test_unwrap();
    }
    let from_b = signed_peer_headers(&node_b, NODE_B, &target, ISSUED_AT, None);
    let error = verify(&access, &from_b, &target, ISSUED_AT, &nonces).test_unwrap_err();
    assert_eq!(error, PeerAuthError::PeerNonceQuotaExhausted);
    assert_eq!(
        error.to_string(),
        "cluster peer has no nonce capacity left in the replay cache"
    );
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    let from_c = signed_peer_headers(&node_c, NODE_C, &target, ISSUED_AT, None);
    verify(&access, &from_c, &target, ISSUED_AT, &nonces).test_unwrap();
}

const GOLDEN_PEER_PAYLOAD: &str = concat!(
    r#"{"bodySha256":"0227e6dc9acbeb361bffe40ced24bc8f2e238b48617d585bd30e3c5f4cbf3caa","#,
    r#""deployment":"dep-a","issuedAt":1792234800,"method":"POST","#,
    r#""nodeId":"https://node-b.example:9101","#,
    r#""nonce":"1111111111111111111111111111111111111111111111111111111111111111","#,
    r#""path":"/v1/internal/cluster/partition","query":"","#,
    r#""recipient":"https://node-a.example:9101","#,
    r#""scheme":"chio.cluster.peer-signature.v1","term":2}"#
);

const GOLDEN_PEER_SIGNATURE: &str = concat!(
    "717af1da49c0ac2917b8de22a4698468ddca0eece498c400e1af3ffdf35cb083",
    "1e8bc67793ee62419c9a0b1af274c326cf235a0da4ac8f208b8281171d29ab0e"
);

#[test]
fn peer_signature_golden_vector() {
    let keypair = Keypair::from_seed(&[7_u8; 32]);
    let target = partition_target();
    let signed = sign_cluster_peer_request(
        &keypair,
        &PeerAddressing {
            deployment: DEPLOYMENT,
            sender: NODE_B,
            recipient: SELF_NODE,
        },
        &target,
        &[0x11_u8; 32],
        ISSUED_AT,
        Some(2),
    )
    .test_unwrap();
    let payload = peer_signature_payload(
        &target,
        &SignedPeerFields {
            deployment: DEPLOYMENT,
            recipient: SELF_NODE,
            node_id: NODE_B,
            body_sha256: &signed.body_sha256,
            nonce: &signed.nonce,
            issued_at: ISSUED_AT,
            term: Some(2),
        },
    )
    .test_unwrap();
    assert_eq!(
        String::from_utf8(payload.as_bytes().to_vec()).test_unwrap(),
        GOLDEN_PEER_PAYLOAD
    );
    assert_eq!(signed.signature, GOLDEN_PEER_SIGNATURE);
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let mut headers = HeaderMap::new();
    for (name, value) in [
        (CLUSTER_NODE_ID_HEADER, NODE_B.to_string()),
        (CLUSTER_AUTH_ISSUED_AT_HEADER, ISSUED_AT.to_string()),
        (
            CLUSTER_AUTH_SIGNATURE_HEADER,
            GOLDEN_PEER_SIGNATURE.to_string(),
        ),
        (CLUSTER_AUTH_NONCE_HEADER, signed.nonce.clone()),
        (CLUSTER_AUTH_BODY_SHA256_HEADER, signed.body_sha256.clone()),
        (CLUSTER_AUTH_TERM_HEADER, "2".to_string()),
    ] {
        headers.insert(name, HeaderValue::from_str(&value).test_unwrap());
    }
    verify(&access, &headers, &target, ISSUED_AT, &nonce_cache()).test_unwrap();
}

#[test]
fn invalid_deployment_tenant_and_peer_node_id_refuse_at_startup() {
    let bad_deployment = config(&reader()).replacen(
        &format!("deployment = \"{DEPLOYMENT}\"\n"),
        "deployment = \" dep-a\"\n",
        1,
    );
    let error = refusal(&bad_deployment);
    assert_eq!(
        error,
        TrustAccessError::InvalidDeployment(" dep-a".to_string())
    );
    assert_eq!(
        error.to_string(),
        "deployment id \" dep-a\" must be 1 to 128 printable characters without surrounding whitespace"
    );
    let bad_tenant = config(&credential(
        "tenant-reader",
        "caller",
        "tenant-secret",
        &["receipts:read"],
        Some(" tenant-a"),
    ));
    let error = refusal(&bad_tenant);
    assert_eq!(
        error,
        TrustAccessError::InvalidTenant {
            credential: "tenant-reader".to_string(),
            tenant: " tenant-a".to_string(),
        }
    );
    assert_eq!(
        error.to_string(),
        "credential \"tenant-reader\" names an invalid tenant id \" tenant-a\""
    );
    let keypair = Keypair::generate();
    let error = refusal(&config(&format!(
        "{}{}",
        reader(),
        peer("  /", &keypair, REPLICA_SCOPES)
    )));
    assert_eq!(
        error,
        TrustAccessError::InvalidPeerNodeId("  /".to_string())
    );
    assert_eq!(error.to_string(), "cluster peer node id \"  /\" is invalid");
}

#[test]
fn peer_pinning_this_nodes_key_refuses() {
    let seed = [9_u8; 32];
    let shared = Keypair::from_seed(&seed);
    let config = parse(&config(&format!(
        "{}{}",
        reader(),
        peer(NODE_B, &shared, REPLICA_SCOPES)
    )))
    .test_unwrap();
    let error = TrustAccess::from_parts(config, Some(Keypair::from_seed(&seed))).test_unwrap_err();
    assert_eq!(
        error,
        TrustAccessError::PeerSharesNodeKey(NODE_B.to_string())
    );
    assert_eq!(
        error.to_string(),
        "cluster peer \"https://node-b.example:9101\" pins this node's own public key"
    );
}

#[test]
fn credential_secret_must_be_clean() {
    for secret in ["", " padded", "padded ", "bell\u{7}"] {
        assert_eq!(
            CredentialSecret::parse(secret.to_string()).test_unwrap_err(),
            InvalidCredentialSecret,
            "{secret:?}"
        );
    }
    let secret = CredentialSecret::parse("operator-secret".to_string()).test_unwrap();
    assert_eq!(format!("{secret:?}"), "CredentialSecret([REDACTED])");
    TrustAccess::single_client(DEPLOYMENT, "finding-operator", &secret).test_unwrap();
}

#[test]
fn peer_signature_over_the_bare_payload_refused() {
    let keypair = Keypair::generate();
    let access = peer_access(NODE_B, &keypair, REPLICA_SCOPES);
    let target = status_target();
    let mut headers = signed_peer_headers(&keypair, NODE_B, &target, ISSUED_AT, None);
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .test_unwrap()
            .to_string()
    };
    let node_id = normalize_cluster_url(NODE_B).test_unwrap();
    let recipient = normalize_cluster_url(SELF_NODE).test_unwrap();
    let nonce = header(CLUSTER_AUTH_NONCE_HEADER);
    let body_sha256 = header(CLUSTER_AUTH_BODY_SHA256_HEADER);
    let signature = header(CLUSTER_AUTH_SIGNATURE_HEADER);
    let payload = peer_signature_payload(
        &target,
        &SignedPeerFields {
            deployment: DEPLOYMENT,
            recipient: &recipient,
            node_id: &node_id,
            body_sha256: &body_sha256,
            nonce: &nonce,
            issued_at: ISSUED_AT,
            term: None,
        },
    )
    .test_unwrap();
    let wrapped = keypair
        .sign_wrapped(CLUSTER_PEER_SIGNATURE_SCHEME, &payload)
        .test_unwrap();
    assert_eq!(signature, wrapped.to_hex());
    let bare = keypair.sign_exempt(
        chio_core::crypto::ExemptFormat::JwsSigningInput,
        payload.as_bytes(),
    );
    headers.insert(
        CLUSTER_AUTH_SIGNATURE_HEADER,
        HeaderValue::from_str(&bare.to_hex()).test_unwrap(),
    );
    let refused = verify(&access, &headers, &target, ISSUED_AT, &nonce_cache()).test_unwrap_err();
    assert_eq!(refused, PeerAuthError::BadSignature);
}
