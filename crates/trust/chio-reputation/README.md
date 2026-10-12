# chio-reputation

Deterministic local reputation scorecards over caller-supplied receipt,
capability-lineage, budget, and incident records. Separate observation feeds
produce bounded deltas and discrete tiers for local consumers.

## Usage

Compute a scorecard with no available history. Configure trusted kernel keys
before adding receipts to the corpus.

```rust
use chio_reputation::{
    compute_local_scorecard, LocalReputationCorpus, MetricValue,
    ReputationConfig, ReputationTier, ScoreDelta, tier_from_deltas,
};

let corpus = LocalReputationCorpus::default();
let config = ReputationConfig::default();
let card = compute_local_scorecard("agent-local", 1_000, &corpus, &config);
assert_eq!(card.composite_score, MetricValue::Unknown);

let deltas = [
    ScoreDelta::from_value("arena_survival", 0.92, 1),
    ScoreDelta::from_value("cross_provider_equality", 0.85, 1),
];
assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier3);
```

## Guarantees

- `compute_local_scorecard` filters receipts by subject attribution, configured
  kernel keys, canonical receipt id, signature, and action hash.
- `ReputationConfig::default` admits no receipt signer. Missing incident input
  and absent evidence remain explicit unknown metrics where applicable.
- `compose_deltas` takes the maximum supplied feed delta. `tier_from_deltas`
  requires score >= 0.90, minimum delta >= 0.80, and two distinct feed ids for
  tier 3; repeated observations from one feed cannot satisfy that gate.
- `build_imported_reputation_signal` applies local issuer/signer, freshness,
  proof-requirement, and attenuation policy to caller-resolved evidence shares.
  Consumers choose how scorecards, import results, and tiers apply.

## Status

Implemented storage-agnostic scoring and feed utilities. Callers gather and
validate lineage, budget, and incident observations, persist their own corpus,
and select local policy. The crate supplies no portable exchange service,
shared-clearing authority, or automatic runtime-admission path. Feed identifiers
are caller-carried labels; distinct labels alone do not authenticate independent
issuers. It declares no Cargo features and is unpublished (`publish = false`).

## Related

- [Architecture](ARCHITECTURE.md)
- [Trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Pheromone substrate](../chio-pheromone/README.md)
- [Core receipt types](../../core/chio-core-types/README.md)

[License](../../../LICENSE)
