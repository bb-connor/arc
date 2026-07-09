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
    // Keys currently present in `insertion_order`, kept in lockstep so a key
    // that is pruned to empty and re-pushed within a single call never gets a
    // SECOND live entry (RFC-0004 F3 residual). O(1) membership keeps the dedupe
    // amortized-constant rather than scanning the deque on every push.
    present: std::collections::HashSet<String>,
    key_cap: usize,
}

impl Default for FederationAdmissionRateLimiter {
    fn default() -> Self {
        // Single-sourced with the process memory budget (RFC-0004 section 5)
        // instead of a duplicated literal; tighter caps use `with_key_cap`.
        Self::from_memory_budget(&chio_kernel::MemoryBudgetConfig::defaults())
    }
}

impl FederationAdmissionRateLimiter {
    /// Build a limiter whose key cap comes from a CONFIGURED process memory
    /// budget. Threading the operator's `MemoryBudgetConfig` (rather than a
    /// fresh `defaults()` read) means lowering `admission_key_cap` on the trust
    /// service config actually tightens this guard instead of being silently
    /// ignored (RFC-0004 F7).
    pub(crate) fn from_memory_budget(budget: &chio_kernel::MemoryBudgetConfig) -> Self {
        Self::with_key_cap(budget.admission_key_cap)
    }

    pub(crate) fn with_key_cap(key_cap: usize) -> Self {
        Self {
            attempts: HashMap::new(),
            insertion_order: std::collections::VecDeque::new(),
            present: std::collections::HashSet::new(),
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
                self.present.remove(&oldest);
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
        if (is_new_key || was_empty) && self.present.insert(key.clone()) {
            // New key, or a key pruned to empty then re-pushed (effectively
            // fresh). `present.insert` returns false when this key already has a
            // live `insertion_order` entry, so a subject that empties and refills
            // its OWN window in one call (F3 residual) keeps exactly ONE entry:
            // no stale front duplicate for the FIFO evictor to pop first and
            // mis-evict a freshly-active key from, and no unbounded deque growth.
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
        let present = &mut self.present;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|t| *t > lower_bound);
            !timestamps.is_empty()
        });
        insertion_order.retain(|entry_key| {
            if attempts.contains_key(entry_key) {
                true
            } else {
                // Drop the `present` marker in lockstep so the dedupe set never
                // outlives the deque entry it guards.
                present.remove(entry_key);
                false
            }
        });

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

    #[test]
    fn lowered_admission_key_cap_from_memory_budget_takes_effect() {
        // F7: the CONFIGURED process memory budget must reach this guard. A
        // budget that lowers `admission_key_cap` to 3 must cap the limiter at 3
        // live keys, not the compiled-in default of 4096.
        let budget = chio_kernel::MemoryBudgetConfig {
            admission_key_cap: 3,
            ..chio_kernel::MemoryBudgetConfig::defaults()
        };
        let mut limiter = FederationAdmissionRateLimiter::from_memory_budget(&budget);
        for i in 0..200u64 {
            let subject = format!("subject-{i}");
            let _ = limiter.check_and_record("policy", &subject, &limit(), 100);
        }
        assert!(
            limiter.key_count() <= 3,
            "configured admission_key_cap did not take effect: {} live keys",
            limiter.key_count()
        );
    }

    #[test]
    fn single_subject_reactivation_keeps_one_insertion_order_entry() {
        // F3 residual: when a subject is the FIRST to observe its own staleness
        // (low-diversity traffic, no other subject interleaves during its idle
        // gap), the re-burst call sees is_new_key=false, empties its own window,
        // and hits the was_empty re-push path. Without the dedupe that pushes a
        // SECOND live insertion_order entry for the same still-live key.
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(2);
        let l = limit();
        let _ = limiter.check_and_record("policy", "solo", &l, 100);
        // Idle strictly past the window, then burst again -- alone, so this call
        // is the first to observe "solo" as stale.
        let _ = limiter.check_and_record("policy", "solo", &l, 100 + l.window_seconds + 1);
        assert_eq!(limiter.key_count(), 1);
        assert_eq!(
            limiter.insertion_order_len(),
            limiter.key_count(),
            "reactivation created a duplicate insertion_order entry: order={} keys={}",
            limiter.insertion_order_len(),
            limiter.key_count(),
        );
    }

    #[test]
    fn reactivation_does_not_leak_or_mis_evict_under_key_cap() {
        // Many burst -> idle-past-window -> burst cycles for a SINGLE subject.
        // Without the dedupe each cycle leaks one insertion_order entry (the
        // deque grows without bound even though only one key is live, RFC-0004),
        // and each leaked entry is a stale front duplicate that the FIFO evictor
        // would pop first, evicting the subject's freshly-active data.
        let l = limit();
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(2);
        for i in 0..32u64 {
            let now = 100 + i * (l.window_seconds + 1);
            let _ = limiter.check_and_record("policy", "solo", &l, now);
        }
        assert_eq!(limiter.key_count(), 1);
        assert_eq!(
            limiter.insertion_order_len(),
            1,
            "single-subject reactivation leaked {} insertion_order entries",
            limiter.insertion_order_len(),
        );

        // Under key_cap pressure the genuinely-oldest LIVE key is evicted and the
        // deque never diverges from `attempts`. "solo" was last active at the end
        // of the loop; two newer distinct subjects arrive inside "solo"'s window,
        // then a third trips the cap and evicts the genuine oldest ("solo").
        let base = 100 + 31 * (l.window_seconds + 1);
        let _ = limiter.check_and_record("policy", "beta", &l, base + 1);
        let _ = limiter.check_and_record("policy", "gamma", &l, base + 2);
        assert!(
            limiter.key_count() <= 2,
            "key cap breached under pressure: {}",
            limiter.key_count()
        );
        assert_eq!(
            limiter.insertion_order_len(),
            limiter.key_count(),
            "insertion_order diverged from attempts under eviction pressure: order={} keys={}",
            limiter.insertion_order_len(),
            limiter.key_count(),
        );
    }
}
