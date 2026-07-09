use super::*;

#[derive(Clone)]
pub(crate) struct TrustServiceState {
    pub(crate) config: TrustServiceConfig,
    pub(crate) enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    pub(crate) verifier_policy_registry: Option<Arc<VerifierPolicyRegistry>>,
    pub(crate) federation_admission_rate_limiter: Arc<Mutex<FederationAdmissionRateLimiter>>,
    pub(crate) cluster: Option<Arc<Mutex<ClusterRuntimeState>>>,
}

#[derive(Clone)]
pub struct TrustControlClient {
    pub(crate) endpoints: Arc<Vec<String>>,
    pub(crate) preferred_index: Arc<Mutex<usize>>,
    pub(crate) token: Arc<str>,
    pub(crate) http: Agent,
    pub(crate) cluster_peer_auth: Option<ClusterPeerClientAuth>,
}

#[derive(Clone)]
pub(crate) struct ClusterPeerClientAuth {
    pub(crate) node_id: Arc<str>,
}

pub(crate) struct RemoteCapabilityAuthority {
    pub(crate) client: TrustControlClient,
    pub(crate) cache: Mutex<AuthorityKeyCache>,
}

pub(crate) struct AuthorityKeyCache {
    pub(crate) current: Option<PublicKey>,
    pub(crate) trusted: Vec<PublicKey>,
    pub(crate) refreshed_at: Instant,
}

pub(crate) struct RemoteRevocationStore {
    pub(crate) client: TrustControlClient,
}

pub(crate) struct RemoteReceiptStore {
    pub(crate) client: TrustControlClient,
}

pub(crate) struct RemoteBudgetStore {
    pub(crate) client: TrustControlClient,
    pub(crate) cached_usage: Mutex<HashMap<(String, u32), BudgetUsageRecord>>,
}

impl TrustServiceState {
    pub(crate) fn enterprise_provider_registry(&self) -> Option<&EnterpriseProviderRegistry> {
        self.enterprise_provider_registry.as_deref()
    }

    pub(crate) fn validated_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Option<&EnterpriseProviderRecord> {
        self.enterprise_provider_registry()
            .and_then(|registry| registry.validated_provider(provider_id))
    }

    pub(crate) fn verifier_policy_registry(&self) -> Option<&VerifierPolicyRegistry> {
        self.verifier_policy_registry.as_deref()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ClusterRuntimeState {
    pub(crate) self_url: String,
    pub(crate) peers: HashMap<String, PeerSyncState>,
    pub(crate) election_term: u64,
    pub(crate) last_leader_url: Option<String>,
    pub(crate) term_started_at: Option<u64>,
    pub(crate) lease_expires_at: Option<u64>,
    pub(crate) lease_ttl_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerSyncState {
    pub(crate) health: PeerHealth,
    pub(crate) partitioned: bool,
    pub(crate) last_error: Option<String>,
    pub(crate) last_contact_at: Option<u64>,
    pub(crate) tool_seq: u64,
    pub(crate) child_seq: u64,
    pub(crate) lineage_seq: u64,
    pub(crate) revocation_cursor: Option<RevocationCursor>,
    pub(crate) budget_cursor: Option<BudgetCursor>,
    pub(crate) delta_records_since_snapshot: u64,
    pub(crate) snapshot_applied_count: u64,
    pub(crate) last_snapshot_at: Option<u64>,
    pub(crate) force_snapshot: bool,
}

#[derive(Debug)]
pub(crate) struct FederationAdmissionRateLimiter {
    attempts: HashMap<String, Vec<u64>>,
    insertion_order: std::collections::VecDeque<String>,
    key_cap: usize,
}

impl Default for FederationAdmissionRateLimiter {
    fn default() -> Self {
        // Single-sourced with the process memory budget (RFC-0004 section 5)
        // instead of a duplicated literal; tighter caps use `with_key_cap`.
        Self::with_key_cap(chio_kernel::MemoryBudgetConfig::defaults().admission_key_cap)
    }
}

impl FederationAdmissionRateLimiter {
    pub(crate) fn with_key_cap(key_cap: usize) -> Self {
        Self {
            attempts: HashMap::new(),
            insertion_order: std::collections::VecDeque::new(),
            key_cap: key_cap.max(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn key_count(&self) -> usize {
        self.attempts.len()
    }

    #[cfg(test)]
    pub(crate) fn insertion_order_len(&self) -> usize {
        self.insertion_order.len()
    }

    pub(crate) fn check_and_record(
        &mut self,
        policy_id: &str,
        subject_key: &str,
        limit: &FederationAdmissionRateLimit,
        now: u64,
    ) -> FederationAdmissionRateLimitStatus {
        let key = format!("{policy_id}:{subject_key}");
        let lower_bound = now.saturating_sub(limit.window_seconds);

        let is_new_key = !self.attempts.contains_key(&key);
        // Key cap with oldest-eviction, mirroring McpRateLimiter: when full and
        // this is a new key, evict the oldest inserted key so a distinct-subject
        // flood saturates instead of growing without bound (RFC-0004 F39).
        if is_new_key && self.attempts.len() >= self.key_cap {
            while let Some(oldest) = self.insertion_order.pop_front() {
                if self.attempts.remove(&oldest).is_some() {
                    break;
                }
            }
        }

        let entry = self.attempts.entry(key.clone()).or_default();
        entry.retain(|timestamp| *timestamp > lower_bound);
        if entry.len() >= limit.max_requests as usize {
            let retry_after_seconds = entry
                .first()
                .map(|oldest| {
                    oldest
                        .saturating_add(limit.window_seconds)
                        .saturating_sub(now)
                })
                .unwrap_or(limit.window_seconds);
            return FederationAdmissionRateLimitStatus {
                limit: limit.max_requests,
                window_seconds: limit.window_seconds,
                remaining: 0,
                retry_after_seconds: Some(retry_after_seconds.max(1)),
            };
        }
        let was_empty = entry.is_empty();
        entry.push(now);
        if is_new_key || was_empty {
            // New key, or a key pruned to empty then re-pushed (effectively
            // fresh): keep insertion order coherent (stale duplicates are skipped
            // by the evict loop's remove guard).
            self.insertion_order.push_back(key);
        }

        // Drop-empty maintenance: prune any key whose window has fully emptied so
        // a fresh subject costs nothing once its window empties (RFC-0004 F39,
        // F21 rate-limiter half). Bounded: touches at most `key_cap` keys.
        // Prune `insertion_order` in lockstep so an expired subject removed from
        // `attempts` cannot leave a stale key behind: otherwise the order deque
        // leaks one String per distinct subject even below `key_cap`, because
        // the eviction loop (which drains stale entries) never runs.
        let attempts = &mut self.attempts;
        let insertion_order = &mut self.insertion_order;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|t| *t > lower_bound);
            !timestamps.is_empty()
        });
        insertion_order.retain(|entry_key| attempts.contains_key(entry_key));

        FederationAdmissionRateLimitStatus {
            limit: limit.max_requests,
            window_seconds: limit.window_seconds,
            remaining: limit.max_requests.saturating_sub(
                self.attempts
                    .get(&format!("{policy_id}:{subject_key}"))
                    .map(|v| v.len())
                    .unwrap_or(0) as u32,
            ),
            retry_after_seconds: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PeerHealth {
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone)]
pub(crate) struct RevocationCursor {
    pub(crate) revoked_at: i64,
    pub(crate) capability_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct BudgetCursor {
    pub(crate) seq: u64,
    pub(crate) updated_at: i64,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ClusterConsensusView {
    pub(crate) self_url: String,
    pub(crate) leader_url: Option<String>,
    pub(crate) role: &'static str,
    pub(crate) has_quorum: bool,
    pub(crate) quorum_size: usize,
    pub(crate) reachable_nodes: usize,
    pub(crate) election_term: u64,
}

impl Default for PeerSyncState {
    fn default() -> Self {
        Self {
            health: PeerHealth::Unknown,
            partitioned: false,
            last_error: None,
            last_contact_at: None,
            tool_seq: 0,
            child_seq: 0,
            lineage_seq: 0,
            revocation_cursor: None,
            budget_cursor: None,
            delta_records_since_snapshot: 0,
            snapshot_applied_count: 0,
            last_snapshot_at: None,
            force_snapshot: true,
        }
    }
}

impl PeerHealth {
    pub(crate) fn is_reachable(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

#[cfg(test)]
mod admission_bound_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn limit() -> FederationAdmissionRateLimit {
        FederationAdmissionRateLimit {
            max_requests: 5,
            window_seconds: 60,
        }
    }

    #[test]
    fn distinct_subject_flood_saturates_at_key_cap() {
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(8);
        for i in 0..1000u64 {
            let subject = format!("subject-{i}");
            let _ = limiter.check_and_record("policy", &subject, &limit(), 100);
        }
        assert!(
            limiter.key_count() <= 8,
            "attempts map grew past key cap: {}",
            limiter.key_count()
        );
    }

    #[test]
    fn expired_subjects_do_not_leak_insertion_order() {
        // Distinct subjects, each in its own window (1000s apart, far past the
        // 60s window), stay below `key_cap`, so the eviction loop never runs. The
        // maintenance pass must prune `insertion_order` alongside `attempts` or
        // the order deque grows one String per subject without bound (RFC-0004
        // F39).
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(4096);
        for i in 0..1000u64 {
            let subject = format!("subject-{i}");
            let now = 100 + i * 1000;
            let _ = limiter.check_and_record("policy", &subject, &limit(), now);
        }
        assert!(
            limiter.insertion_order_len() <= 8,
            "insertion_order leaked stale keys: {}",
            limiter.insertion_order_len()
        );
        assert!(
            limiter.key_count() <= 8,
            "attempts leaked stale keys: {}",
            limiter.key_count()
        );
    }

    #[test]
    fn emptied_window_key_leaves_no_residue() {
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(4096);
        let _ = limiter.check_and_record("policy", "s", &limit(), 100);
        assert_eq!(limiter.key_count(), 1);
        // A later call whose window has fully passed prunes the old timestamp;
        // the drop-empty maintenance pass then removes the residual key from the
        // unrelated emptied subject, so only "s2" remains.
        let _ = limiter.check_and_record("policy", "s2", &limit(), 100_000);
        assert_eq!(limiter.key_count(), 1, "emptied-window key left residue");
    }
}
