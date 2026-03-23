# Velocity Guards

The `VelocityGuard` in `crates/pact-guards/src/velocity.rs` limits how fast an agent can invoke tools using a token bucket algorithm. It operates as a synchronous `Guard` in the kernel pipeline, sitting before the tool server receives the request.

## Token Bucket Rate Limiting

Each `(capability_id, grant_index)` pair gets its own independent token bucket. Buckets for different grants within the same capability token are isolated; exhausting one grant's bucket does not affect another. Buckets for different capability tokens are also isolated.

On each invocation the guard calls `bucket.try_consume(1.0)`. The bucket refills continuously at a rate of `max_invocations_per_window / window_secs` tokens per second. If the bucket has at least 1 token available the invocation is allowed and one token is consumed. If the bucket is empty the guard returns `Verdict::Deny` (not an error).

## VelocityConfig

```rust
pub struct VelocityConfig {
    pub max_invocations_per_window: Option<u32>,
    pub max_spend_per_window: Option<u64>,
    pub window_secs: u64,
    pub burst_factor: f64,
}
```

**`max_invocations_per_window`**: Maximum number of invocations allowed within the window. `None` means unlimited invocations. When set, the bucket capacity is `max_invocations_per_window * burst_factor` and the refill rate is `max_invocations_per_window / window_secs`.

**`max_spend_per_window`**: Maximum monetary spend (in the same minor-unit denomination as `MonetaryAmount`) within the window. `None` means unlimited spend. This uses a separate bucket from the invocation bucket.

**`window_secs`**: Window duration in seconds. Default: 60. A window of 60 with `max_invocations_per_window = 10` allows 10 invocations per minute at a steady rate.

**`burst_factor`**: Multiplier on the bucket capacity above the steady-state rate. Default: `1.0` (no burst). A factor of `2.0` allows a burst of up to `2 * max_invocations_per_window` calls before the bucket empties, after which the steady refill rate governs.

Default configuration has both limits as `None` (unlimited), `window_secs = 60`, and `burst_factor = 1.0`.

## Configuration Example

Allow at most 30 invocations per minute with no burst:

```rust
use pact_guards::velocity::{VelocityConfig, VelocityGuard};

let guard = VelocityGuard::new(VelocityConfig {
    max_invocations_per_window: Some(30),
    max_spend_per_window: None,
    window_secs: 60,
    burst_factor: 1.0,
});
```

Allow at most 10 invocations per minute with a burst of 20:

```rust
let guard = VelocityGuard::new(VelocityConfig {
    max_invocations_per_window: Some(10),
    max_spend_per_window: None,
    window_secs: 60,
    burst_factor: 2.0,
});
```

## Interaction with Monetary Budgets

Velocity guards and monetary budgets are independent enforcement layers. The `VelocityGuard` runs in the guard pipeline before the budget store is charged. A request denied by the velocity guard never reaches `try_charge_cost`, so it does not consume any monetary budget.

The `max_spend_per_window` field in `VelocityConfig` currently consumes 1 spend unit per invocation regardless of actual tool cost. Phase 8 integration will wire actual cost values into the spend bucket. Until then, `max_spend_per_window` can be used as a secondary invocation rate limit expressed in cost units.

When both `max_invocations_per_window` and `max_spend_per_window` are set, both buckets must have available capacity for an invocation to proceed. The invocation bucket is checked first; if it denies, the spend bucket is not checked.

## Guard Pipeline Placement

`VelocityGuard` implements the `Guard` trait:

```rust
impl Guard for VelocityGuard {
    fn name(&self) -> &str { "velocity" }
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> { ... }
}
```

Register it with the kernel's guard pipeline in your setup code. The guard is thread-safe (`Mutex`-protected buckets) and designed for synchronous use without async overhead.
