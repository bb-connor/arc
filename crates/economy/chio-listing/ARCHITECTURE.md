# chio-listing architecture

## Responsibility and boundary

The crate owns registry publication shapes, search and comparison, local
trust-activation decisions, and outcome contracts. `GenericListingArtifact`
represents a namespace-owned actor. `Listing` pairs that signed artifact
with a signed pricing hint, publisher metadata, and replica freshness.
`GenericTrustActivationArtifact` records a separate local operator decision.

Consumers supply reports, keys, time, and policy. The library has no registry
database, network fetcher, runtime admission installer, or collateral store.
`GenericListingBoundary` requires explicit activation and preserves the
publication surface as visibility-only.

## Structure

`listing.rs` defines actor kinds, namespace ownership, lifecycle states,
signed listings, queries, and reports. `search.rs` defines freshness windows,
ranking policy, replica results, errors, and divergence records. `util.rs`
implements namespace normalization, validation, owner-signature checks,
aggregation, and deterministic ranking.

`discovery.rs` adds pricing hints, SLA fields, marketplace queries, `search`,
`compare`, and `resolve_admissible_listing`. `trust_activation.rs` defines
activation eligibility, issuance inputs, evaluation inputs, and refusal codes.

The public `outcome` module separates contracts, predicate evaluation,
evidence, delivery checkpoints and acknowledgements, and verdicts. Its wire
loaders and verification functions use bounded canonical inputs and explicit
signer-trust objects.

## Data and control flow

1. A publisher supplies a `GenericListingReport` with namespace ownership,
   report freshness, search policy, and signed actor listings.
2. `aggregate_generic_listing_reports` validates each report, rejects stale
   reports, applies query filters, and groups matching replica observations.
3. Conflicting source-artifact digests, lifecycle states, or ownership fields
   create divergence records and remove that replica group from results.
4. `search` pairs surviving active listings with valid, live pricing hints.
   It checks namespace, owner key, operator identity, and requested filters.
5. Results sort by currency, price, revocation rate, receipt volume, and
   listing identifier. Query limits cap returned rows at 200.
6. Runtime consumers evaluate a separately signed trust activation under
   their pinned local operator key.

Aggregation ranks replicas using freshness, publisher role, age, and stable
identity fields. Marketplace price ordering is implemented separately.
`compare` computes relative price indexes and copies SLA and freshness fields;
it does not measure provider behavior.

## Trust and invariants

`GenericListingArtifact::validate` checks schema, required identity fields,
namespace consistency, URL forms, expiry ordering, subject metadata, and
the publication boundary. Compatibility reference validation requires
nonempty provenance fields; consumers authenticate the referenced artifact.

Owner checking verifies the export envelope and compares its signer with
`namespace_ownership.signer_public_key`. That key is declared inside the
listing. The helper establishes internal consistency; external namespace
ownership policy remains with its caller.

`search` validates hint bodies and signatures, checks their current window,
and binds them to listing and publisher authority. Invalid hint and report
inputs appear in `ListingSearchResponse::errors`.
`aggregate_generic_listing_reports` exposes divergence diagnostics and counts
in `GenericListingSearchResponse`. Marketplace `search` excludes divergent
groups but omits those diagnostics from `ListingSearchResponse`. Lists,
counters, and sorting are held in local memory.

`Listing::is_admissible_at` checks active status, pricing liveness, and the
retained freshness-state marker. It does not reassess the report's age at
the new time or check the listing's own expiry. Consumers must refresh the
report and apply listing-expiry policy before using a retained result.

`evaluate_generic_trust_activation` defaults to refusal. It checks the
listing signature, local activation signer, exact listing body digest,
publication time, freshness, activation expiry, disposition, and eligibility.
Public-untrusted admission and required bond backing remain non-admitted.
The evaluation time and current publisher/freshness are supplied inputs;
the caller must obtain them from trusted current state.

Outcome verifiers use `OutcomeSignerTrustV1`, explicit binding contexts,
and current-window checks. `load_canonical_outcome_json` bounds original
bytes to 4 MiB and requires exact canonical input before decoding. Outcome
artifacts express pricing and delivery evidence for downstream execution;
this crate does not dispatch settlement.

## Dependencies

`chio-core-types` supplies export envelopes, signatures, canonical JSON,
receipt types, and `MonetaryAmount`. `serde` and `serde_json` implement wire
serialization and outcome JSON evaluation. `thiserror` represents outcome
rejections. `chio-spec-validate` is a development dependency for schema tests.

## Verification

`src/tests.rs` tests generic aggregation, namespace conflicts, freshness,
activation bindings, and admission refusal. `tests/search_compare.rs` checks
marketplace ranking, signatures, hint filtering, and comparison fields.
`tests/outcome.rs` exercises outcome schemas, typed constructors, predicate
evaluation, authority bindings, and delivery/verdict transitions.

Run `cargo test -p chio-listing` for unit and integration coverage. Persistent
replication, operator ownership policy, and runtime installation require
verification in the service that consumes these contracts.
