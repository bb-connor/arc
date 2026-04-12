# Phase 117 Verification

Phase `117` is complete.

## What changed

- Added a generic signed listing and namespace model in `arc-core` for tool
  servers, credential issuers, credential verifiers, liability providers, and
  future registry actors.
- Added public trust-control endpoints for signed namespace resolution and
  generic listing search over the operator's current certification, issuer,
  verifier, and liability-provider surfaces.
- Added fail-closed namespace-consistency checks so contradictory ownership and
  namespace mismatch are rejected rather than projected as valid open-registry
  state.
- Updated protocol, qualification, release, audit, and partner-proof docs to
  describe one bounded open-listing substrate that preserves visibility without
  granting trust admission.

## Validation

Passed:

- `cargo fmt --all`
- `cargo check -p arc-core -p arc-kernel -p arc-cli`
- `CARGO_INCREMENTAL=0 cargo test -p arc-core listing -- --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p arc-cli --test certify certify_public_generic_registry_namespace_and_listings_project_current_actor_families -- --exact --nocapture`

Pending procedural follow-up:

- hosted `CI`
- hosted `Release Qualification`
- Nyquist validation artifacts for phases `113` through `117`

## Outcome

`OPENX-01` is now satisfied. ARC has one signed generic registry substrate for
operator-owned public actor listings, while explicit trust activation, search
ranking, and governance-network semantics remain future bounded layers.
