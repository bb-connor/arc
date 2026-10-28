use super::*;
use chio_control_plane::trust_control::caller_credentials::{
    sign_cluster_peer_request, PeerAddressing, PeerRequestTarget, CLUSTER_AUTH_BODY_SHA256_HEADER,
    CLUSTER_AUTH_NONCE_HEADER,
};

fn internal_peer_registry() -> &'static Mutex<HashMap<String, String>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn internal_listen_registry() -> &'static Mutex<HashMap<String, SocketAddr>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, SocketAddr>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn trust_cluster_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(super) fn register_internal_peer(base_url: &str, peer_urls: &[String]) {
    let mut registry = internal_peer_registry()
        .lock()
        .expect("lock internal peer registry");
    if let Some(peer_url) = peer_urls.first() {
        registry.insert(base_url.to_string(), peer_url.clone());
    } else {
        registry.remove(base_url);
    }
}

pub(super) fn internal_peer_node_id(base_url: &str) -> Option<String> {
    internal_peer_registry()
        .lock()
        .expect("lock internal peer registry")
        .get(base_url)
        .cloned()
}

/// The internal listener address of the node advertised at `node_url`,
/// reserved on first use so every peer pins the same address.
pub(super) fn internal_listen(node_url: &str) -> SocketAddr {
    *internal_listen_registry()
        .lock()
        .expect("lock internal listen registry")
        .entry(node_url.to_string())
        .or_insert_with(reserve_listen_addr)
}

pub(super) fn internal_url(node_url: &str) -> String {
    format!("http://{}", internal_listen(node_url))
}

/// Deterministic test node key for `node_url`.
pub(super) fn node_keypair(node_url: &str) -> Keypair {
    let digest = sha256_hex(format!("chio-cli-test-node:{node_url}").as_bytes());
    Keypair::from_seed_hex(&digest[..64]).expect("test node seed")
}

/// Write the node key seed for `node_url` to a fresh private file.
pub(super) fn write_node_key_file(node_url: &str) -> PathBuf {
    let digest = sha256_hex(format!("chio-cli-test-node:{node_url}").as_bytes());
    trust_access::write_private(&digest[..64], "seed")
}

/// Headers for a request from `sender` to the node advertised at `base_url`,
/// signed with the sender's node key over the exact path, query and body.
pub(super) fn signed_internal_headers(
    base_url: &str,
    sender: &str,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    term: Option<u64>,
) -> Vec<(&'static str, String)> {
    let issued_at = i64::try_from(chio_test_support::clock::unix_seconds()).expect("issued_at");
    let mut nonce = [0_u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let signed = sign_cluster_peer_request(
        &node_keypair(sender),
        &PeerAddressing {
            deployment: trust_access::TEST_DEPLOYMENT,
            sender,
            recipient: base_url,
        },
        &PeerRequestTarget {
            method,
            path,
            query,
            body,
        },
        &nonce,
        issued_at,
        term,
    )
    .expect("sign test peer request");
    let mut headers = vec![
        (CLUSTER_NODE_ID_HEADER, sender.to_string()),
        (CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string()),
        (CLUSTER_AUTH_SIGNATURE_HEADER, signed.signature),
        (CLUSTER_AUTH_NONCE_HEADER, signed.nonce),
        (CLUSTER_AUTH_BODY_SHA256_HEADER, signed.body_sha256),
    ];
    if let Some(term) = term {
        headers.push((CLUSTER_AUTH_TERM_HEADER, term.to_string()));
    }
    headers
}

/// The access configuration for one test node: the full client credential
/// for `service_token`, and for a clustered node its identity and the pins
/// of every peer.
pub(super) fn write_node_access_config(
    service_token: &str,
    advertise_url: &str,
    peer_urls: &[String],
) -> PathBuf {
    let internal_listen = internal_listen(advertise_url).to_string();
    let key_file = write_node_key_file(advertise_url);
    let peer_entries: Vec<(String, String, String)> = peer_urls
        .iter()
        .map(|peer_url| {
            (
                peer_url.clone(),
                internal_url(peer_url),
                node_keypair(peer_url).public_key().to_hex(),
            )
        })
        .collect();
    let peers: Vec<trust_access::TestPeer<'_>> = peer_entries
        .iter()
        .map(
            |(node_id, internal_url, public_key_hex)| trust_access::TestPeer {
                node_id,
                internal_url,
                public_key_hex,
            },
        )
        .collect();
    let cluster = trust_access::TestCluster {
        node_id: advertise_url,
        node_key_file: &key_file,
        peers: &peers,
    };
    let text = trust_access::access_config_text(
        service_token,
        &[],
        &internal_listen,
        (!peer_urls.is_empty()).then_some(&cluster),
    );
    trust_access::write_private(&text, "toml")
}
