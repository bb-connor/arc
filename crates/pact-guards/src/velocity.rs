//! Velocity guard -- synchronous token bucket rate limiting per grant.
//!
//! Prevents runaway tool usage by throttling agent invocations per
//! (capability_id, grant_index) pair using a token bucket algorithm.
//! The guard uses `std::sync::Mutex` (synchronous, no async) and fits
//! into the existing `Guard` pipeline.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use pact_kernel::{Guard, GuardContext, KernelError, Verdict};

// ---------------------------------------------------------------------------
// TokenBucket (private)
// ---------------------------------------------------------------------------

struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, amount: f64) -> bool {
        self.refill();
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
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
    invocation_buckets: Mutex<HashMap<(String, usize), TokenBucket>>,
    spend_buckets: Mutex<HashMap<(String, usize), TokenBucket>>,
    config: VelocityConfig,
}

impl VelocityGuard {
    /// Create a new `VelocityGuard` with the given configuration.
    pub fn new(config: VelocityConfig) -> Self {
        Self {
            invocation_buckets: Mutex::new(HashMap::new()),
            spend_buckets: Mutex::new(HashMap::new()),
            config,
        }
    }
}

impl Guard for VelocityGuard {
    fn name(&self) -> &str {
        "velocity"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let grant_index = ctx.matched_grant_index.unwrap_or(0);
        let key = (ctx.request.capability.id.clone(), grant_index);

        // Check invocation rate limit
        if let Some(max_inv) = self.config.max_invocations_per_window {
            let capacity = max_inv as f64 * self.config.burst_factor;
            let window_secs = self.config.window_secs.max(1) as f64;
            let refill_rate = max_inv as f64 / window_secs;

            let mut buckets = self.invocation_buckets.lock().map_err(|_| {
                KernelError::Internal("velocity guard invocation lock poisoned".to_string())
            })?;
            let bucket = buckets
                .entry(key.clone())
                .or_insert_with(|| TokenBucket::new(capacity, refill_rate));
            if !bucket.try_consume(1.0) {
                return Ok(Verdict::Deny);
            }
        }

        // Check spend rate limit
        if let Some(max_spend) = self.config.max_spend_per_window {
            let capacity = max_spend as f64 * self.config.burst_factor;
            let window_secs = self.config.window_secs.max(1) as f64;
            let refill_rate = max_spend as f64 / window_secs;

            let mut buckets = self.spend_buckets.lock().map_err(|_| {
                KernelError::Internal("velocity guard spend lock poisoned".to_string())
            })?;
            let bucket = buckets
                .entry(key)
                .or_insert_with(|| TokenBucket::new(capacity, refill_rate));
            // Consume 1 unit per invocation; Phase 8 integration will pass actual cost.
            if !bucket.try_consume(1.0) {
                return Ok(Verdict::Deny);
            }
        }

        Ok(Verdict::Allow)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use pact_core::capability::{CapabilityToken, CapabilityTokenBody, PactScope};
    use pact_core::crypto::Keypair;

    use super::*;

    // Helper: build a minimal ToolCallRequest.
    fn make_request(
        cap: &CapabilityToken,
        agent_id: &str,
        server_id: &str,
    ) -> pact_kernel::ToolCallRequest {
        pact_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap.clone(),
            tool_name: "read_file".to_string(),
            server_id: server_id.to_string(),
            agent_id: agent_id.to_string(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
        }
    }

    fn signed_cap(kp: &Keypair, cap_id: &str) -> CapabilityToken {
        let scope = PactScope::default();
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

    fn guard_ctx<'a>(
        request: &'a pact_kernel::ToolCallRequest,
        scope: &'a PactScope,
        agent_id: &'a String,
        server_id: &'a String,
        grant_index: Option<usize>,
    ) -> pact_kernel::GuardContext<'a> {
        pact_kernel::GuardContext {
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
        let scope = PactScope::default();
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
        let scope = PactScope::default();
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
        let scope = PactScope::default();
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
        let scope = PactScope::default();
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
        let scope = PactScope::default();
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
        let scope = PactScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();

        let request_a = pact_kernel::ToolCallRequest {
            request_id: "req-a".to_string(),
            capability: cap_a.clone(),
            tool_name: "read_file".to_string(),
            server_id: server.clone(),
            agent_id: agent.clone(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
        };
        let request_b = pact_kernel::ToolCallRequest {
            request_id: "req-b".to_string(),
            capability: cap_b.clone(),
            tool_name: "read_file".to_string(),
            server_id: server.clone(),
            agent_id: agent.clone(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
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
        let scope = PactScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            guard.evaluate(&ctx).expect("should not error");
        }

        // The result must be Ok(Verdict::Deny), not Err.
        let ctx = guard_ctx(&request, &scope, &agent, &server, None);
        let result = guard.evaluate(&ctx);
        assert!(result.is_ok(), "rate limit must return Ok, not Err");
        assert_eq!(result.expect("ok"), Verdict::Deny, "must be Verdict::Deny");
    }

    #[test]
    fn spend_velocity_allows_up_to_limit() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(3),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-spend");
        let scope = PactScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        for i in 0..3 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            let result = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(
                result,
                Verdict::Allow,
                "spend request {i} should be allowed"
            );
        }

        let ctx = guard_ctx(&request, &scope, &agent, &server, None);
        let result = guard.evaluate(&ctx).expect("should not error");
        assert_eq!(result, Verdict::Deny, "4th spend request should be denied");
    }
}
