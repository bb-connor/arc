# chio-link architecture

## Responsibility and boundary

`ChioLinkOracle` owns configured rate resolution, an in-memory price cache,
mutable operator controls, and runtime health reports. `PriceOracle` exposes
`get_rate` and supported pairs; `OracleBackend` injects a source returning an
`ExchangeRate`. Applications supply configuration and authorize feed sources.

Conversion and evidence projection are separate functions. The crate returns
unsigned observations and does not mutate a grant budget or store a receipt.
Callers reconcile conversions with authoritative charging and sign evidence
at the boundary that accepts responsibility for the observation.

## Structure

| Module | Responsibility |
| --- | --- |
| `lib` | Rate validation, backend selection, cache resolution and runtime controls. |
| `config` | Pair/feed policies, networks, egress configuration and validation. |
| `chainlink`, `sequencer` | Contract-backed price and L2 uptime RPC reads. |
| `pyth` | Hermes REST price observations and decimal-to-rational projection. |
| `cache` | Latest values and bounded rolling observations. |
| `circuit_breaker`, `convert` | Divergence checks and checked minor-unit conversion. |
| `control`, `monitor`, `reports` | Operator/report artifacts and health classification. |
| `source` | Local request-error source with sanitized display text. |

With `web3` disabled, Chainlink/sequencer module paths select disabled
implementations. Pyth and conversion remain usable; configured Chainlink
construction or requests fail with `UnsupportedBackend`. Sequencer reads
without a configured uptime feed return `None`.

## Data and control flow

Constructors validate configuration; injected backends must match configured
kinds when supplied. `get_rate` resolves the pair, samples system time, and
checks global pause, pair enablement, chain enablement, and sequencer state.
These checks run before cached values can be returned.

Cache resolution checks pair equality and source freshness. Stale cache entries
return an error unless a configured degraded override permits a larger age
window and additional margin. A missing cache entry triggers backend refresh;
a stale error normally propagates instead of implicitly refreshing.

Refresh first honors a forced backend. Otherwise it reads the primary and,
when configured/allowed for the pair, attempts the secondary. Two successful
reads must pass divergence policy. Secondary failure permits a valid primary;
primary failure uses the available fallback. Accepted rates enter the cache.

## Trust and invariants

`ExchangeRate::ensure_fresh` rejects zero denominators, future update times,
and updates beyond `max_age_seconds`. Runtime/backend paths also check pair
identity. Low-level conversion does not call this freshness function itself.

Chainlink and sequencer RPC use the contract-backed Alloy transport and bounded
`HttpEgressContract` responses. Hermes HTTP dispatch uses the same egress
boundary, matches the requested feed ID, and validates the price/time shape.
Hermes observations do not carry a Pyth signature verification step here.
Provider truth and configured feed provenance therefore remain trust inputs.

The cache limits observations by count and window. Its `twap` calculation is
an equal-weight arithmetic mean of normalized observations, rounded upward;
unequal observation intervals receive equal weights. Cache/control state is
held under Tokio read/write locks and disappears when the process exits.

`convert_units` checks scales, denominator, multiplication, margin application,
and `u64` result width, rounding both conversion and margin upward.
`to_conversion_evidence` checks freshness and rate width, copies caller cost
and currency fields, and sets both oracle key and signature to `None`.
It does not prove the supplied converted amount equals a particular conversion.

## Dependencies

`chio-core` supplies the oracle evidence contract. `chio-egress-contract` owns
HTTP destination, redirect, DNS, and response-bound checks. Optional Alloy
packages and Tower implement Chainlink JSON-RPC; reqwest implements Hermes.
Tokio supports asynchronous I/O and state locks. Serde/JSON encode operator
artifacts and decode feed data; `thiserror` defines typed oracle failures.

## Verification

Use `cargo test -p chio-link --features web3` and `cargo test -p chio-link`.
Runtime tests inject backends to check pair/freshness mismatch, divergence,
pauses, fallback controls, and degraded mode. Cache tests check rolling
observations and averaging; conversion tests check scales, margin, and ceiling
rounding. RPC tests use loopback servers and can skip when binding is
unavailable. Integration smoke tests cover rate helpers and default config.
These local fixtures do not establish independent feed correctness.

[README](README.md) · [Web3 artifacts](../chio-web3/README.md)
