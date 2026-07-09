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
    // Per-subject in-window attempt timestamps, keyed by `policy:subject`. The
    // distinct-key set is bounded fail-closed by `key_cap`: EXPIRED (out-of-
    // window) subjects are pruned first, and once the table holds `key_cap`
    // ACTIVE (in-window) subjects a new subject is DENIED rather than evicting an
    // active bucket. Never evicting an ACTIVE bucket closes the reset-by-eviction
    // bypass (an attacker cannot force its own active bucket out with throwaway
    // subjects and then reuse its subject with a fresh limit in the same window)
    // (RFC-0004 F39, codex finding 3553826807), while still saturating instead of
    // growing under a distinct-subject flood. A subject is removed only when its
    // window fully empties.
    attempts: HashMap<String, Vec<u64>>,
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
            key_cap: key_cap.max(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn key_count(&self) -> usize {
        self.attempts.len()
    }

    /// Drop subjects whose entire attempt window has expired, freeing slots for
    /// new subjects. Bounded: touches at most the live keys (<= `key_cap` once
    /// saturated).
    fn prune_expired(&mut self, lower_bound: u64) {
        self.attempts.retain(|_, timestamps| {
            timestamps.retain(|t| *t > lower_bound);
            !timestamps.is_empty()
        });
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
        // Key cap (RFC-0004 F39). When the table is full and this is a new
        // subject, prune EXPIRED (out-of-window) subjects first to reclaim slots.
        // If every remaining slot still holds an ACTIVE (in-window) subject, DENY
        // the new subject fail-closed rather than evicting an active bucket:
        // evicting an active bucket would reset its per-window limit, so an
        // attacker could reset its own limit by flooding throwaway subjects to
        // force its eviction, then reusing its subject in the same window (codex
        // finding 3553826807, FAIL-OPEN). Denying keeps memory bounded (cap
        // unchanged) without the bypass, and a distinct-subject flood still
        // saturates instead of growing.
        if is_new_key && self.attempts.len() >= self.key_cap {
            self.prune_expired(lower_bound);
            if self.attempts.len() >= self.key_cap {
                return FederationAdmissionRateLimitStatus {
                    limit: limit.max_requests,
                    window_seconds: limit.window_seconds,
                    remaining: 0,
                    retry_after_seconds: Some(limit.window_seconds.max(1)),
                };
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
        entry.push(now);

        // Drop-empty maintenance: prune any subject whose window has fully
        // emptied so a fresh subject costs nothing once its window empties
        // (RFC-0004 F39, F21 rate-limiter half). Bounded: touches at most
        // `key_cap` keys. The subject just recorded above retains its `now`
        // timestamp, so it survives.
        self.prune_expired(lower_bound);

        FederationAdmissionRateLimitStatus {
            limit: limit.max_requests,
            window_seconds: limit.window_seconds,
            remaining: limit
                .max_requests
                .saturating_sub(self.attempts.get(&key).map(|v| v.len()).unwrap_or(0) as u32),
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
    fn expired_subjects_do_not_leak_keys() {
        // Distinct subjects, each in its own window (1000s apart, far past the
        // 60s window), stay below `key_cap`. The drop-empty maintenance pass must
        // prune expired subjects from `attempts` or the map grows one key per
        // subject without bound (RFC-0004 F39).
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(4096);
        for i in 0..1000u64 {
            let subject = format!("subject-{i}");
            let now = 100 + i * 1000;
            let _ = limiter.check_and_record("policy", &subject, &limit(), now);
        }
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
    fn single_subject_reactivation_keeps_one_key() {
        // A single subject that empties its window and re-bursts must stay exactly
        // one key (keyed by `policy:subject`), never leaking a residual entry.
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(2);
        let l = limit();
        let _ = limiter.check_and_record("policy", "solo", &l, 100);
        // Idle strictly past the window, then burst again.
        let _ = limiter.check_and_record("policy", "solo", &l, 100 + l.window_seconds + 1);
        assert_eq!(limiter.key_count(), 1);
    }

    #[test]
    fn full_table_of_active_subjects_denies_new_subject_without_eviction() {
        // The cap must never evict an ACTIVE (in-window) subject to admit a new
        // one; the new subject is DENIED fail-closed instead. Two in-window
        // subjects fill a cap of 2, so a third distinct subject is denied and the
        // two actives keep their buckets intact (RFC-0004 F39, finding 3553826807).
        let l = limit();
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(2);
        let a = limiter.check_and_record("policy", "a", &l, 100);
        let b = limiter.check_and_record("policy", "b", &l, 100);
        assert!(a.retry_after_seconds.is_none() && b.retry_after_seconds.is_none());

        // "c" trips the cap while a and b are both in-window: c is denied, and no
        // active bucket is evicted.
        let c = limiter.check_and_record("policy", "c", &l, 100);
        assert_eq!(c.remaining, 0);
        assert!(
            c.retry_after_seconds.is_some(),
            "new subject must be denied when the table is full of active buckets, not admitted by eviction"
        );
        assert_eq!(
            limiter.key_count(),
            2,
            "an active bucket was wrongly evicted"
        );

        // "a" retained its bucket: re-recording it reflects its two in-window
        // attempts (remaining = 5 - 2 = 3), proving it was not reset by eviction.
        let a2 = limiter.check_and_record("policy", "a", &l, 100);
        assert_eq!(a2.remaining, 3, "active subject a was reset by eviction");
    }

    #[test]
    fn active_bucket_not_evicted_by_throwaway_subject_flood() {
        // codex finding 3553826807 (FAIL-OPEN): with max_requests=1 and a small
        // key cap, a subject must not be able to reset its own in-window rate
        // limit by flooding a throwaway subject to force its bucket's eviction,
        // then reusing its own subject in the same window.
        let l = FederationAdmissionRateLimit {
            max_requests: 1,
            window_seconds: 1000,
        };
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(1);
        let now = 100;

        // The attacker spends its single allowed request for the window.
        let first = limiter.check_and_record("policy", "attacker", &l, now);
        assert_eq!(first.remaining, 0);
        assert!(
            first.retry_after_seconds.is_none(),
            "the first request must be allowed"
        );

        // A throwaway subject tries to evict the attacker's ACTIVE bucket. The
        // table is full of an active bucket, so the throwaway is DENIED (not
        // admitted by evicting the attacker).
        let throwaway = limiter.check_and_record("policy", "throwaway", &l, now);
        assert!(
            throwaway.retry_after_seconds.is_some(),
            "throwaway must be denied, not admitted by evicting the active bucket"
        );
        assert_eq!(
            limiter.key_count(),
            1,
            "the attacker's active bucket must survive the throwaway flood"
        );

        // The attacker reuses its subject in the SAME window: it must stay
        // rate-limited. Before the fix the throwaway evicted the attacker, so this
        // returned a fresh allowed bucket (retry_after_seconds = None) -- the
        // bypass (RED). After the fix the attacker is still denied (GREEN).
        let replay = limiter.check_and_record("policy", "attacker", &l, now);
        assert_eq!(replay.remaining, 0);
        assert!(
            replay.retry_after_seconds.is_some(),
            "attacker must stay rate-limited in-window; eviction bypass regressed"
        );
    }
}
