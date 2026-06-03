# chio-link Architecture

`chio-link` owns Chio's cross-currency oracle runtime. It reads Chainlink and Pyth feeds, enforces typed HTTP egress contracts, checks sequencer uptime, applies circuit-breaker divergence policy, caches fresh rates, converts budget units, and emits `OracleConversionEvidence` under the `chio-link` oracle authority.

The crate is split into oracle configuration, Chainlink and Pyth backends, cache and TWAP logic, conversion math, circuit-breaker checks, runtime monitoring, and operator control-state traces. `ChioLinkOracle` is the main trust boundary: every backend response must be fresh, pair-exact, and policy-checked before cache insertion or evidence construction can use it.

The security constraint is auditable rate exactness. Pair symbols, feed references, source labels, update timestamps, denominators, cache age, conversion margins, and converted units must remain unambiguous across backend reads, cache reuse, degraded mode, and receipt evidence.

Planned improvement: reject backend rates whose `base` or `quote` differs from the configured pair before circuit-breaker comparison or cache insertion, so injected or fallback backends cannot poison evidence with a mismatched currency label.
