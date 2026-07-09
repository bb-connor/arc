//! Velocity guard -- synchronous token bucket rate limiting per grant.
//!
//! Prevents runaway tool usage by throttling agent invocations per
//! (capability_id, grant_index) pair using a token bucket algorithm.
//! The guard uses `std::sync::Mutex` (synchronous, no async) and fits
//! into the existing `Guard` pipeline.
//!
//! All arithmetic uses integer milli-tokens (u64) to eliminate accumulated
//! floating-point drift. The refill rate is expressed as milli-tokens per
//! millisecond.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

// ---------------------------------------------------------------------------
// TokenBucket (private)
// ---------------------------------------------------------------------------

/// Token bucket using integer milli-token arithmetic to avoid floating-point
/// drift. One logical token == 1_000 milli-tokens.
///
/// Fields:
///   capacity_mt     -- maximum bucket level in milli-tokens
///   tokens_mt       -- current level in milli-tokens
///   refill_rate_mpm -- refill rate in milli-tokens per millisecond
///   last_refill     -- wall-clock instant of last refill
struct TokenBucket {
    capacity_mt: u64,
    tokens_mt: u64,
    /// Milli-tokens added per millisecond of elapsed time.
    refill_rate_mpm: u64,
    last_refill: Instant,
}

/// Milli-tokens per logical token.
const MT_PER_TOKEN: u64 = 1_000;

impl TokenBucket {
    /// Create a new bucket.
    ///
    /// `capacity_tokens`   -- maximum logical tokens (burst ceiling)
    /// `window_secs`       -- window duration used to derive the refill rate
    /// `max_per_window`    -- logical tokens added per window
    fn new(capacity_tokens: u64, max_per_window: u64, window_secs: u64) -> Self {
        // refill_rate_mpm = (max_per_window * MT_PER_TOKEN) / (window_secs * 1000 ms/s)
        // We keep a minimum rate of 1 milli-token/ms to avoid divide-by-zero and
        // ensure very slow rates still make progress.
        let window_ms = window_secs.saturating_mul(1_000).max(1);
        let refill_rate_mpm = (max_per_window.saturating_mul(MT_PER_TOKEN))
            .checked_div(window_ms)
            .unwrap_or(1)
            .max(1);

        Self {
            capacity_mt: capacity_tokens.saturating_mul(MT_PER_TOKEN),
            tokens_mt: capacity_tokens.saturating_mul(MT_PER_TOKEN),
            refill_rate_mpm,
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume `amount_tokens` logical tokens. Returns true on
    /// success (tokens were available), false if the bucket is too empty.
    fn try_consume(&mut self, amount_tokens: u64) -> bool {
        self.refill();
        let cost_mt = amount_tokens.saturating_mul(MT_PER_TOKEN);
        if self.tokens_mt >= cost_mt {
            self.tokens_mt -= cost_mt;
            true
        } else {
            false
        }
    }

    /// Refill the bucket based on elapsed time since the last refill.
    fn refill(&mut self) {
        let elapsed_ms = self.last_refill.elapsed().as_millis() as u64;
        if elapsed_ms == 0 {
            return;
        }
        let added = elapsed_ms.saturating_mul(self.refill_rate_mpm);
        self.tokens_mt = self.tokens_mt.saturating_add(added).min(self.capacity_mt);
        self.last_refill = Instant::now();
    }
}

// ---------------------------------------------------------------------------
// VelocityConfig
// ---------------------------------------------------------------------------

/// Configuration for `VelocityGuard`.
#[derive(Clone, Debug)]
pub struct VelocityConfig {
    /// Maximum invocations per window. None means unlimited.
    pub max_invocations_per_window: Option<u32>,
    /// Maximum spend (monetary units) per window. None means unlimited.
    pub max_spend_per_window: Option<u64>,
    /// Window duration in seconds.
    pub window_secs: u64,
    /// Burst factor (1.0 = no burst above steady rate).
    pub burst_factor: f64,
}

impl Default for VelocityConfig {
    fn default() -> Self {
        Self {
            max_invocations_per_window: None,
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        }
    }
}

// ---------------------------------------------------------------------------
// VelocityGuard
// ---------------------------------------------------------------------------

/// Guard that rate-limits agent invocations using synchronous token buckets.
///
/// Buckets are keyed by `(capability_id, grant_index)` so different grants
/// within the same capability can have independent rate limits.
pub struct VelocityGuard {
    /// Both bucket maps live behind ONE mutex so the combined-cap check and the
    /// insert are atomic across both maps: no evaluate() ever samples a stale
    /// sibling-map size, so the combined `invocation + spend` bucket count stays
    /// bounded by `bucket_cap` even under concurrent evaluate() calls for
    /// distinct capability ids (RFC-0004 F38, codex finding 3553826793). A single
    /// lock also removes any cross-map lock ordering, so there is no deadlock.
    state: Mutex<VelocityState>,
    config: VelocityConfig,
    bucket_cap: usize,
}

/// Combined bucket state guarded by a single mutex (see [`VelocityGuard::state`]).
struct VelocityState {
    invocation_buckets: HashMap<(String, usize), TokenBucket>,
    spend_buckets: HashMap<(String, usize), TokenBucket>,
    invocation_inserts_since_sweep: usize,
    spend_inserts_since_sweep: usize,
}

/// Which of the two combined maps an operation targets.
#[derive(Clone, Copy)]
enum BucketKind {
    Invocation,
    Spend,
}

impl VelocityGuard {
    /// Create a new `VelocityGuard` with the given configuration and the
    /// bounded-memory default bucket cap, sourced from
    /// [`chio_kernel::MemoryBudgetConfig`]'s `velocity_bucket_cap` so the cap is
    /// single-sourced with the process memory budget rather than a duplicated
    /// literal. Deployments that need a tighter cap use
    /// [`Self::with_bucket_cap`] (RFC-0004 F38).
    pub fn new(config: VelocityConfig) -> Self {
        Self::with_bucket_cap(
            config,
            chio_kernel::MemoryBudgetConfig::defaults().velocity_bucket_cap,
        )
    }

    /// Create a `VelocityGuard` with an explicit total-bucket cap so a
    /// self-minted-leaf flood saturates rather than growing (RFC-0004 F38). The
    /// cap is a TOTAL across BOTH the invocation and spend maps. Because both maps
    /// share one mutex, the combined-cap check and the insert are atomic: no
    /// evaluate() reads a stale sibling-map size, so the combined bucket count is
    /// bounded by `bucket_cap` (a tight, provable bound for `bucket_cap >= 3`)
    /// even under concurrent evaluate() calls for distinct capability ids, rather
    /// than the un-folded `2 * bucket_cap` or an unbounded concurrent overshoot.
    pub fn with_bucket_cap(config: VelocityConfig, bucket_cap: usize) -> Self {
        Self {
            state: Mutex::new(VelocityState {
                invocation_buckets: HashMap::new(),
                spend_buckets: HashMap::new(),
                invocation_inserts_since_sweep: 0,
                spend_inserts_since_sweep: 0,
            }),
            config,
            bucket_cap: bucket_cap.max(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn invocation_bucket_count(&self) -> usize {
        match self.state.lock() {
            Ok(g) => g.invocation_buckets.len(),
            Err(poisoned) => poisoned.into_inner().invocation_buckets.len(),
        }
    }

    #[cfg(test)]
    pub(crate) fn spend_bucket_count(&self) -> usize {
        match self.state.lock() {
            Ok(g) => g.spend_buckets.len(),
            Err(poisoned) => poisoned.into_inner().spend_buckets.len(),
        }
    }

    /// Combined bucket count across BOTH maps read under the single lock, so it is
    /// a consistent snapshot (never a torn read across two separate locks).
    #[cfg(test)]
    pub(crate) fn combined_bucket_count(&self) -> usize {
        match self.state.lock() {
            Ok(g) => g.invocation_buckets.len() + g.spend_buckets.len(),
            Err(poisoned) => {
                let g = poisoned.into_inner();
                g.invocation_buckets.len() + g.spend_buckets.len()
            }
        }
    }
}

impl VelocityState {
    /// Combined bucket count across both maps.
    fn combined_len(&self) -> usize {
        self.invocation_buckets
            .len()
            .saturating_add(self.spend_buckets.len())
    }

    /// Amortized idle-sweep of both maps plus COMBINED-cap enforcement before a
    /// new key is inserted into `kind`'s map. Run under the single state lock, so
    /// `combined_len()` is always the true current total (never a stale sibling
    /// snapshot). A full-and-idle bucket is semantically a fresh one, so idle
    /// buckets are periodically dropped from BOTH maps.
    ///
    /// The cap is enforced only when INSERTING a genuinely new key: updating an
    /// existing bucket must never evict, otherwise a repeat request for an
    /// already-tracked capability could evict and recreate its own bucket with a
    /// full token balance, defeating the per-window limit (RFC-0004 F38). When a
    /// new insert would reach the combined cap, the most-idle bucket across BOTH
    /// maps is evicted -- excluding the active `key` in either map so the bucket
    /// being consumed by this evaluate is never reset. Because the combined size
    /// is the true total under one lock, the combined count stays bounded by
    /// `bucket_cap` (tight for `bucket_cap >= 3`) rather than overshooting under
    /// concurrency (codex finding 3553826793).
    fn sweep_and_enforce_combined_cap(
        &mut self,
        kind: BucketKind,
        window_secs: u64,
        bucket_cap: usize,
        key: &(String, usize),
    ) {
        let do_sweep = {
            let counter = match kind {
                BucketKind::Invocation => &mut self.invocation_inserts_since_sweep,
                BucketKind::Spend => &mut self.spend_inserts_since_sweep,
            };
            *counter = counter.saturating_add(1);
            if *counter >= 256 {
                *counter = 0;
                true
            } else {
                false
            }
        };
        if do_sweep {
            let idle = std::time::Duration::from_secs(window_secs);
            self.invocation_buckets
                .retain(|_, bucket| bucket.last_refill.elapsed() < idle);
            self.spend_buckets
                .retain(|_, bucket| bucket.last_refill.elapsed() < idle);
        }

        let target_has_key = match kind {
            BucketKind::Invocation => self.invocation_buckets.contains_key(key),
            BucketKind::Spend => self.spend_buckets.contains_key(key),
        };
        if target_has_key {
            return;
        }

        // Evict until inserting one new bucket keeps the combined total within
        // `bucket_cap`. `combined_len()` is the true total under this lock, so
        // there is no stale-snapshot overshoot. The loop stops only when the
        // combined total is below the cap or when the only remaining buckets are
        // the excluded active `key` (bounded: at most two such entries).
        while self.combined_len() >= bucket_cap {
            if !self.evict_most_idle_excluding(key) {
                break;
            }
        }
    }

    /// Evict the single most-idle bucket (largest elapsed since `last_refill`)
    /// across BOTH maps whose map-key is not `exclude`. Returns true if a bucket
    /// was removed.
    fn evict_most_idle_excluding(&mut self, exclude: &(String, usize)) -> bool {
        let mut victim: Option<(BucketKind, (String, usize), std::time::Duration)> = None;
        for (k, b) in self.invocation_buckets.iter() {
            if k == exclude {
                continue;
            }
            let idle = b.last_refill.elapsed();
            let better = match &victim {
                None => true,
                Some((_, _, best)) => idle > *best,
            };
            if better {
                victim = Some((BucketKind::Invocation, k.clone(), idle));
            }
        }
        for (k, b) in self.spend_buckets.iter() {
            if k == exclude {
                continue;
            }
            let idle = b.last_refill.elapsed();
            let better = match &victim {
                None => true,
                Some((_, _, best)) => idle > *best,
            };
            if better {
                victim = Some((BucketKind::Spend, k.clone(), idle));
            }
        }
        match victim {
            Some((BucketKind::Invocation, k, _)) => {
                self.invocation_buckets.remove(&k);
                true
            }
            Some((BucketKind::Spend, k, _)) => {
                self.spend_buckets.remove(&k);
                true
            }
            None => false,
        }
    }
}

impl Guard for VelocityGuard {
    fn name(&self) -> &str {
        "velocity"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let grant_index = ctx.matched_grant_index.unwrap_or(0);
        let key = (ctx.request.capability.id.clone(), grant_index);

        let window_secs = self.config.window_secs.max(1);

        // Both maps share ONE lock, held for the whole evaluate, so the
        // combined-cap check and the insert are atomic across both maps: no
        // evaluate() ever reads a stale sibling-map size, so the combined bucket
        // count cannot overshoot under concurrency (RFC-0004 F38, codex finding
        // 3553826793). A single lock means no cross-map lock ordering and no
        // deadlock. If spend limiting fails closed below, the guard drops cleanly
        // (no panic, no poison).
        let mut state = self
            .state
            .lock()
            .map_err(|_| KernelError::Internal("velocity guard state lock poisoned".to_string()))?;

        // Check invocation rate limit.
        if let Some(max_inv) = self.config.max_invocations_per_window {
            // Burst capacity: max_inv * burst_factor, rounded to nearest integer.
            let capacity = ((max_inv as f64 * self.config.burst_factor).round() as u64).max(1);
            state.sweep_and_enforce_combined_cap(
                BucketKind::Invocation,
                window_secs,
                self.bucket_cap,
                &key,
            );
            let bucket = state
                .invocation_buckets
                .entry(key.clone())
                .or_insert_with(|| TokenBucket::new(capacity, max_inv as u64, window_secs));
            if !bucket.try_consume(1) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // Check spend rate limit.
        if let Some(max_spend) = self.config.max_spend_per_window {
            let capacity = ((max_spend as f64 * self.config.burst_factor).round() as u64).max(1);
            let spend_units = planned_spend_units(ctx)?;
            state.sweep_and_enforce_combined_cap(
                BucketKind::Spend,
                window_secs,
                self.bucket_cap,
                &key,
            );
            let bucket = state
                .spend_buckets
                .entry(key)
                .or_insert_with(|| TokenBucket::new(capacity, max_spend, window_secs));
            if !bucket.try_consume(spend_units) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        Ok(GuardDecision::allow())
    }
}

fn planned_spend_units(ctx: &GuardContext) -> Result<u64, KernelError> {
    let grant_index = ctx.matched_grant_index.ok_or_else(|| {
        KernelError::Internal(
            "velocity guard spend limiting requires matched_grant_index".to_string(),
        )
    })?;
    let grant = ctx.scope.grants.get(grant_index).ok_or_else(|| {
        KernelError::Internal(format!(
            "velocity guard could not resolve grant index {grant_index}"
        ))
    })?;
    grant
        .max_cost_per_invocation
        .as_ref()
        .map(|amount| amount.units)
        .ok_or_else(|| {
            KernelError::Internal(
                "velocity guard spend limiting requires max_cost_per_invocation on the matched grant"
                    .to_string(),
            )
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use chio_core::capability::{
        scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;

    use super::*;

    // Helper: build a minimal ToolCallRequest.
    fn make_request(
        cap: &CapabilityToken,
        agent_id: &str,
        server_id: &str,
    ) -> chio_kernel::ToolCallRequest {
        chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap.clone(),
            tool_name: "read_file".to_string(),
            server_id: server_id.to_string(),
            agent_id: agent_id.to_string(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    fn signed_cap(kp: &Keypair, cap_id: &str) -> CapabilityToken {
        let scope = ChioScope::default();
        let body = CapabilityTokenBody {
            id: cap_id.to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope,
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        CapabilityToken::sign(body, kp).expect("sign cap")
    }

    fn spend_scope(max_cost_per_invocation: u64) -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: max_cost_per_invocation,
                    currency: "USD".to_string(),
                }),
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        }
    }

    fn guard_ctx<'a>(
        request: &'a chio_kernel::ToolCallRequest,
        scope: &'a ChioScope,
        agent_id: &'a String,
        server_id: &'a String,
        grant_index: Option<usize>,
    ) -> chio_kernel::GuardContext<'a> {
        chio_kernel::GuardContext {
            request,
            scope,
            agent_id,
            server_id,
            session_filesystem_roots: None,
            matched_grant_index: grant_index,
        }
    }

    #[test]
    fn guard_name_is_velocity() {
        let guard = VelocityGuard::new(VelocityConfig::default());
        assert_eq!(guard.name(), "velocity");
    }

    #[test]
    fn idle_buckets_are_swept_and_key_count_is_capped() {
        // Cap tiny so the flood saturates rather than grows.
        let config = VelocityConfig {
            max_invocations_per_window: Some(1000),
            ..VelocityConfig::default()
        };
        let guard = VelocityGuard::with_bucket_cap(config, 8);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        // Drive many distinct capability ids (the self-minted-leaf flood): each
        // makes a new bucket, but the cap holds the total.
        for i in 0..500u64 {
            let cap = signed_cap(&kp, &format!("cap-{i}"));
            let scope = ChioScope::default();
            let request = make_request(&cap, &agent, &server);
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            let _ = guard.evaluate(&ctx);
        }
        assert!(
            guard.invocation_bucket_count() <= 8,
            "bucket map grew past cap: {}",
            guard.invocation_bucket_count()
        );
    }

    #[test]
    fn both_bucket_maps_together_stay_within_total_cap() {
        // RFC-0004 F38 round-2: with both invocation and spend limits enabled the
        // documented bucket cap is a TOTAL across both maps. Flooding distinct
        // capability ids (each mints an invocation AND a spend bucket) must not
        // let invocation + spend buckets exceed the cap (the per-map bug would
        // reach 2x the cap).
        let config = VelocityConfig {
            max_invocations_per_window: Some(1000),
            max_spend_per_window: Some(1000),
            window_secs: 60,
            burst_factor: 1.0,
        };
        let cap_total = 8;
        let guard = VelocityGuard::with_bucket_cap(config, cap_total);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        // A grant with max_cost_per_invocation so the spend path mints buckets.
        let scope = spend_scope(1);
        for i in 0..500u64 {
            let cap = signed_cap(&kp, &format!("cap-{i}"));
            let request = make_request(&cap, &agent, &server);
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let _ = guard.evaluate(&ctx);
        }
        let combined = guard.invocation_bucket_count() + guard.spend_bucket_count();
        assert!(
            combined <= cap_total,
            "combined bucket count {combined} exceeded total cap {cap_total} (inv={}, spend={})",
            guard.invocation_bucket_count(),
            guard.spend_bucket_count(),
        );
        // Both maps are genuinely populated, so the bound is meaningful.
        assert!(
            guard.invocation_bucket_count() > 0 && guard.spend_bucket_count() > 0,
            "test is vacuous: one of the maps stayed empty"
        );
    }

    #[test]
    fn combined_cap_holds_under_concurrent_distinct_capability_flood() {
        // RFC-0004 F38 (codex finding 3553826793, REAL fix not docs): concurrent
        // evaluate() calls for distinct capability ids used to sample a stale
        // sibling-map size, so both maps could grow past the combined cap. With
        // both maps under one lock the combined-cap check and insert are atomic,
        // so the combined bucket count never exceeds `bucket_cap`. This test
        // hammers the guard from many threads with distinct capability ids (each
        // mints an invocation AND a spend bucket) and asserts the combined count
        // stays within the cap at every observation.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let config = VelocityConfig {
            max_invocations_per_window: Some(1000),
            max_spend_per_window: Some(1000),
            window_secs: 60,
            burst_factor: 1.0,
        };
        let bucket_cap = 16usize;
        let guard = Arc::new(VelocityGuard::with_bucket_cap(config, bucket_cap));
        let max_observed = Arc::new(AtomicUsize::new(0));

        let threads = 8usize;
        let per_thread = 400u64;
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let guard = Arc::clone(&guard);
                let max_observed = Arc::clone(&max_observed);
                thread::spawn(move || {
                    let kp = Keypair::generate();
                    let agent = kp.public_key().to_hex();
                    let server = "srv".to_string();
                    let scope = spend_scope(1);
                    for i in 0..per_thread {
                        // Distinct capability id per (thread, iteration): each is a
                        // brand-new key, exercising the new-key insert + cap path.
                        let cap = signed_cap(&kp, &format!("cap-{t}-{i}"));
                        let request = make_request(&cap, &agent, &server);
                        let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
                        let _ = guard.evaluate(&ctx);
                        // Observe the combined count under the single lock: it must
                        // never exceed the cap. Before the fix the stale sibling
                        // snapshot let concurrent inserts overshoot this bound.
                        let combined = guard.combined_bucket_count();
                        max_observed.fetch_max(combined, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }

        let observed = max_observed.load(Ordering::Relaxed);
        assert!(
            observed <= bucket_cap,
            "combined bucket count {observed} exceeded the total cap {bucket_cap} under concurrency"
        );
        // The bound is meaningful only if buckets were actually created.
        assert!(
            observed > 0,
            "test is vacuous: no buckets were ever created"
        );
    }

    #[test]
    fn updating_existing_bucket_at_cap_is_not_evicted() {
        // Cap of 1 with a 1-per-window limit: the first request for a capability
        // consumes its only token; a second request for the SAME capability must
        // find the preserved (now empty) bucket and be denied, not evict and
        // recreate it with a full balance (RFC-0004 F38 / cap-on-update).
        let config = VelocityConfig {
            max_invocations_per_window: Some(1),
            window_secs: 60,
            ..VelocityConfig::default()
        };
        let guard = VelocityGuard::with_bucket_cap(config, 1);
        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-update");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        let first = guard
            .evaluate(&guard_ctx(&request, &scope, &agent, &server, None))
            .expect("first request should not error");
        assert_eq!(first, Verdict::Allow, "first request should be allowed");

        let second = guard
            .evaluate(&guard_ctx(&request, &scope, &agent, &server, None))
            .expect("second request should not error");
        assert_eq!(
            second,
            Verdict::Deny,
            "second request must hit the preserved (empty) bucket, not a fresh one"
        );
        assert_eq!(
            guard.invocation_bucket_count(),
            1,
            "the bucket being consumed must not be evicted and recreated"
        );
    }

    #[test]
    fn velocity_config_defaults_unlimited() {
        let config = VelocityConfig::default();
        assert!(config.max_invocations_per_window.is_none());
        assert!(config.max_spend_per_window.is_none());
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.burst_factor, 1.0);
    }

    #[test]
    fn unlimited_config_always_allows() {
        let guard = VelocityGuard::new(VelocityConfig::default());
        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-unlimited");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();

        let request = make_request(&cap, &agent, &server);
        for _ in 0..100 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            let result = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(result, Verdict::Allow);
        }
    }

    #[test]
    fn allows_requests_up_to_limit() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(5),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-limited");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        for i in 0..5 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            let result = guard.evaluate(&ctx).expect("evaluate should not error");
            assert_eq!(
                result,
                Verdict::Allow,
                "request {i} should be allowed (limit=5)"
            );
        }
    }

    #[test]
    fn denies_request_exceeding_limit() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(5),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-exceed");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust the 5 allowed tokens.
        for _ in 0..5 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            guard.evaluate(&ctx).expect("should not error");
        }

        // 6th request must be denied.
        let ctx = guard_ctx(&request, &scope, &agent, &server, None);
        let result = guard.evaluate(&ctx).expect("should not error");
        assert_eq!(result, Verdict::Deny, "6th request should be denied");
    }

    #[test]
    fn tokens_refill_after_window() {
        // 1-second window with limit=2.  After 1.1 seconds the bucket should
        // have refilled enough to allow at least one more request.
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(2),
            max_spend_per_window: None,
            window_secs: 1,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-refill");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust the bucket.
        for _ in 0..2 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            guard.evaluate(&ctx).expect("should not error");
        }

        // Verify it denies now.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            let result = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(result, Verdict::Deny, "should deny before refill");
        }

        // Wait for window to pass.
        thread::sleep(Duration::from_millis(1100));

        // Must allow again after refill.
        let ctx = guard_ctx(&request, &scope, &agent, &server, None);
        let result = guard.evaluate(&ctx).expect("should not error");
        assert_eq!(result, Verdict::Allow, "should allow after refill");
    }

    #[test]
    fn separate_buckets_for_different_grant_indices() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(1),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-multi-grant");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust grant_index 0.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Allow, "grant 0 first request");
        }
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Deny, "grant 0 second request denied");
        }

        // grant_index 1 should have a fresh bucket.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(1));
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Allow, "grant 1 first request should allow");
        }
    }

    #[test]
    fn separate_buckets_for_different_capability_ids() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(1),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap_a = signed_cap(&kp, "cap-a");
        let cap_b = signed_cap(&kp, "cap-b");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();

        let request_a = chio_kernel::ToolCallRequest {
            request_id: "req-a".to_string(),
            capability: cap_a.clone(),
            tool_name: "read_file".to_string(),
            server_id: server.clone(),
            agent_id: agent.clone(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let request_b = chio_kernel::ToolCallRequest {
            request_id: "req-b".to_string(),
            capability: cap_b.clone(),
            tool_name: "read_file".to_string(),
            server_id: server.clone(),
            agent_id: agent.clone(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        // Exhaust cap-a.
        {
            let ctx = guard_ctx(&request_a, &scope, &agent, &server, None);
            guard.evaluate(&ctx).expect("should not error");
        }
        {
            let ctx = guard_ctx(&request_a, &scope, &agent, &server, None);
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Deny, "cap-a second request denied");
        }

        // cap-b should be unaffected.
        {
            let ctx = guard_ctx(&request_b, &scope, &agent, &server, None);
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Allow, "cap-b first request should allow");
        }
    }

    #[test]
    fn returns_verdict_deny_not_err_when_rate_limited() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(1),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-deny-type");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            guard.evaluate(&ctx).expect("should not error");
        }

        // The result must be Ok(GuardDecision::deny(Vec::new())), not Err.
        let ctx = guard_ctx(&request, &scope, &agent, &server, None);
        let result = guard.evaluate(&ctx);
        assert!(result.is_ok(), "rate limit must return Ok, not Err");
        assert_eq!(result.expect("ok"), Verdict::Deny, "must be Verdict::Deny");
    }

    #[test]
    fn spend_velocity_allows_up_to_limit() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(300),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-spend");
        let scope = spend_scope(100);
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        for i in 0..3 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let result = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(
                result,
                Verdict::Allow,
                "spend request {i} should be allowed"
            );
        }

        let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
        let result = guard.evaluate(&ctx).expect("should not error");
        assert_eq!(result, Verdict::Deny, "4th spend request should be denied");
    }

    #[test]
    fn spend_velocity_consumes_planned_cost_units() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(250),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-spend-costed");
        let scope = spend_scope(125);
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        let first = guard.evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)));
        assert_eq!(first.expect("first spend request"), Verdict::Allow);

        let second = guard.evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)));
        assert_eq!(second.expect("second spend request"), Verdict::Allow);

        let third = guard.evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)));
        assert_eq!(third.expect("third spend request"), Verdict::Deny);
    }

    #[test]
    fn spend_velocity_requires_cost_metadata_on_matched_grant() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(10),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-spend-missing-cost");
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        };
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        let error = guard
            .evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)))
            .expect_err("missing cost metadata should fail closed");
        assert!(
            error.to_string().contains("max_cost_per_invocation"),
            "unexpected error: {error}"
        );
    }
}
