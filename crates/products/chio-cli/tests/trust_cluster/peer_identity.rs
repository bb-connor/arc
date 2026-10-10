use super::*;

fn internal_peer_registry() -> &'static Mutex<HashMap<String, String>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
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

pub(super) fn cluster_peer_auth_signature(
    service_token: &str,
    node_id: &str,
    endpoint: &str,
    issued_at: i64,
    term: Option<u64>,
) -> String {
    let payload = canonical_json_bytes(&json!({
        "scheme": CLUSTER_AUTH_SCHEME,
        "serviceToken": service_token,
        "nodeId": node_id,
        "endpoint": endpoint,
        "issuedAt": issued_at,
        "term": term,
    }))
    .expect("encode cluster peer auth payload");
    sha256_hex(&payload)
}
