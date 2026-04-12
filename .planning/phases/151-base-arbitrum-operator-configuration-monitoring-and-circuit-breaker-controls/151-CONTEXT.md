# Phase 151: Base/Arbitrum Operator Configuration, Monitoring, and Circuit-Breaker Controls - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Add the operator-facing configuration and runtime safety surface inside
`arc-link` so Base-first cross-currency budget enforcement can be run with
explicit trusted-chain policy, structured health visibility, sequencer-aware
fail-closed behavior, and deterministic operator overrides.

</domain>

<decisions>
## Implementation Decisions

### Operator Policy Shape
- Keep the kernel-facing `PriceOracle` trait unchanged so existing kernel
  integration from phase `150` continues to work.
- Extend `arc-link` configuration with an explicit operator policy block rather
  than inventing a new service or CLI surface in this phase.
- Model Base as the active default chain and Arbitrum as an explicit
  operator-visible secondary chain inventory so later web3 milestones can
  consume the same chain metadata without redefining trust configuration.

### Monitoring and Alerting
- Emit structured runtime health reports from `arc-link` itself instead of
  coupling phase `151` to a separate metrics backend.
- Report chain health, pair health, active backend, last successful read,
  alert severity, and current override state in one reviewable artifact shape.
- Treat sequencer downtime, divergence trips, operator pause, and fallback or
  degraded reads as distinct statuses so operators can tell outage from spend
  exhaustion.

### Degraded Mode
- Keep the default posture fail closed.
- Allow one explicit degraded-mode policy that can reuse the last cached rate
  only within a bounded grace window and only with extra conservative margin.
- Treat sequencer downtime or post-recovery grace as hard-stop conditions for
  cross-currency enforcement rather than a degraded path.

### Circuit-Breaker and Overrides
- Support one global pause plus pair-level disable and backend-selection
  overrides.
- Keep operator overrides additive and explicit in runtime reports so ARC does
  not silently widen trust.
- Preserve later settlement and anchoring automation work as future scope.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-link/src/lib.rs` already owns the `PriceOracle` contract, cache
  lookup, primary or fallback routing, and divergence enforcement path.
- `crates/arc-link/src/config.rs` already models pair policy and is the right
  place for trusted-chain and override configuration.
- `crates/arc-link/src/cache.rs` already holds the latest and TWAP-capable rate
  state that degraded-mode handling can reuse.
- `crates/arc-kernel/src/lib.rs` already treats oracle failures conservatively,
  so new operator controls can fail by returning explicit oracle errors.

### Established Patterns
- ARC favors additive typed report artifacts over hidden mutable runtime state.
- Bounded support surfaces are documented in `docs/standards/` and later wired
  into release and protocol docs.
- Tests live close to the crate and use deterministic in-memory backends for
  failure-path coverage.

### Integration Points
- `ArcLinkOracle::get_rate`, `cached_rate`, and `refresh_pair` are the narrow
  points where operator policy and monitoring should attach.
- `docs/standards/ARC_LINK_BASE_MAINNET_CONFIG.json` is the current machine-
  readable config artifact and should evolve into the richer operator surface.
- Kernel cross-currency reconciliation from phase `150` will automatically
  consume new fail-closed oracle errors and any conservative margin embedded in
  returned exchange rates.

</code_context>

<specifics>
## Specific Ideas

- Use the official Chainlink L2 sequencer uptime feed addresses for Base and
  Arbitrum in the operator chain inventory.
- Keep the `arc-link` report surface library-native and JSON-serializable so
  later CLI or hosted admin endpoints can reuse it directly.
- Fix the Base LINK feed pin to the canonical Base address documented in the
  shared web3 contract architecture notes.

</specifics>

<deferred>
## Deferred Ideas

- External metrics exporters or alert transport integrations.
- Chainlink Data Streams premium tier.
- Full Arbitrum pair activation and multi-chain settlement consumption, which
  belong to later `arc-anchor` and `arc-settle` milestones.

</deferred>
