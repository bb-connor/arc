# chio-underwriting Architecture

`chio-underwriting` owns underwriting policy input, decision, simulation, appeal, premium pricing, and marketplace credit-limit contracts. It consumes Chio receipt, appraisal, runtime-assurance, reputation, certification, and settlement evidence without depending on the kernel.

The main crate models underwriting artifacts and evaluator logic. `premium` owns deterministic premium pricing and fail-closed input validation. `marketplace_limits` owns the reputation-tiered credit-limit helper consumed by market and credit surfaces.

The security constraint is that malformed evidence or pricing inputs must not silently produce broader economic authority. Invalid policies, stale or weak evidence, bad premium configuration, and revoked publisher state must deny, step up, or withhold instead of approving.

Planned improvement: reject non-finite behavioral premium thresholds so anomaly penalties cannot be disabled through an invalid floating-point configuration.
