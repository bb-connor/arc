# chio-reputation architecture

## Responsibility and boundary

`compute_local_scorecard` scores one subject at a supplied time against a
`LocalReputationCorpus` and `ReputationConfig`.
The corpus includes receipts, normalized capability lineage, grant usage, and
optional incident records. Scorecards expose metric availability alongside a
composite score and effective weight sum. Imported signals add provenance, issuer identity,
local policy, acceptance reasons, and attenuated score.

This crate owns no database or kernel hook. Its `chio-core` dependency is the
core-types package alias. Callers obtain observations, select trusted kernel
keys, validate lineage and budget sources, and choose downstream policy.
Portable signing/exchange, federated clearing, and capability admission are
separate trust-control surfaces.

## Structure

| Source | Responsibility |
|--------|----------------|
| `lib` | Receipt integrity/authority filtering and public exports |
| `model` | Corpus records, metrics, config, scorecards, import policy/types |
| `score` | Subject filtering, metrics, decay, weighted composition |
| `compare` | History/delegation/reliability metrics and import evaluation |
| `issuance` | Attribution, subset/TTL/budget reduction, numeric helpers |
| `input` | Duplicate-aware capability-scope JSON decoding |
| `feed` | Feed trait, bounded deltas, maximum/minimum composition |
| `feeds` | Arena survival and cross-provider equality observations |
| `tier` | Fixed threshold table and discovery-floor comparison |

Several source files are included into the crate root, so their public types
and functions are root exports. `feed`, `feeds`, and `tier` are public modules.

## Data and control flow

1. Build a capability-id map from the supplied normalized lineage records.
2. Attribute receipts using signed attribution metadata or the corpus's
   capability mapping, then filter them through receipt integrity checks.
3. Select subject capabilities and delegations issued by the subject.
4. Calculate boundary pressure, resource stewardship, least privilege, history
   depth, specialization, delegation hygiene, reliability, and incident metrics.
5. Compose available metrics using configured weights and return explicit
   unknown values when evidence needed by a metric is missing.
6. `build_imported_reputation_signal` evaluates a bilateral evidence share
   against local identity, trust-mode, proof, age, and attenuation policy.
   A separate feed pipeline derives tiers from observation deltas.

Temporal metrics use the supplied time and configured exponential half-life.
The corpus owns timestamp truth; this scoring function does not fetch fresh
status or independently attest when an observation occurred.

## Trust and invariants

Receipt integrity requires a configured kernel-key string, recomputed canonical
receipt id, valid receipt signature, and valid action parameter hash. The empty
default trusted-key set filters all receipts and emits a one-time warning when
integrity evaluation encounters that configuration. This is not the finding
verifier's strict Ed25519 and authenticated lifecycle boundary.

Lineage, budget usage, and incidents are normalized caller inputs. They are not
cryptographically authenticated here. Receipt authority checks additionally
require an allowed decision where a metric relies on successful authority.
An unavailable incident feed differs from an explicitly supplied empty feed.
Incident scoring consumes the whole supplied incident list without subject
filtering, so callers must scope that list before scoring an individual agent.
Import evaluation treats empty issuer/signer allowlists as unrestricted and uses
caller-carried proof requirements and identity fields. It checks timestamp
ordering and age with saturating subtraction; it does not independently verify
a signed share or reject future export time. A network-cleared trust-mode
requirement rejects the bilateral mode returned by this helper.

`ScoreDelta::from_value` converts negative/nonfinite values to zero and caps
positive values at one. Its fields are public, so callers should use that
constructor for bounded observations. For normalized inputs, `compose_deltas`
selects the maximum, and Tier 3 requires at least two distinct labels with every
supplied delta meeting its floor. Directly constructed NaN values bypass the
minimum comparison. Feed identity labels do not prove independent issuers or
an anti-sybil trust root.

## Dependencies

`chio-core-types` supplies receipt, scope, signing, and canonical JSON types.
`serde` and `serde_json` encode scorecards and scope inputs. `tracing` surfaces
the empty trust configuration. `proptest` supplies test-only monotonicity checks.
No kernel, transport, or persistent-store dependency is present.

## Verification

Run `cargo test -p chio-reputation` from the workspace root.
`tests/local_reputation.rs` exercises signed receipts, lineage attribution,
unknown metrics, scope reduction, and relative scorecards.
Imported-signal unit tests cover signer identity, ambiguous fields, trust mode,
and import/export timestamp ordering.
`tests/feed_monotonicity.rs` exercises feed composition and tier properties.
Unit tests cover constructor clamping and distinct-feed tier gates.
The README executes empty-corpus scoring and two-label tier mapping locally.
