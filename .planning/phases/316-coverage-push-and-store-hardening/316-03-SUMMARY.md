# Summary 316-03

Phase `316` added a third execution wave aimed at two still-weak bounded crates
with concentrated public validation logic: `arc-anchor` and `arc-listing`.
The work avoided already-strong happy paths and instead filled missing failure
branches and on-chain/request guardrails.

The implemented coverage wave added new tests in:

- `arc-anchor`
- `arc-listing`

Measured gains from targeted tarpaulin runs:

- `arc-anchor`: `476/852` -> `662/852` (`+186`)
- `arc-listing`: `434/605` -> `530/605` (`+96`)

Verification that passed during this wave:

- `cargo test -p arc-anchor`
- `cargo test -p arc-listing`
- targeted tarpaulin run for `arc-anchor`
- targeted tarpaulin run for `arc-listing`
- `git diff --check -- crates/arc-anchor/src/evm.rs crates/arc-anchor/Cargo.toml`
- `git diff --check -- crates/arc-listing/src/lib.rs`

The added `arc-anchor` tests cover EVM publication preparation failures,
delegate registration validation, JSON-RPC success/error envelopes, root
confirmation, publication guard decoding, and on-chain inclusion verification.

The added `arc-listing` tests cover namespace/listing/search validation plus a
wide set of trust-activation failure modes, including unverifiable listings,
invalid activation artifacts, listing mismatches, divergent freshness, expired
activations, denied/pending activations, ineligible actor/publisher/status/operator
constraints, and bond-backed review-visible outcomes.

Even with these measured deltas, the workspace estimate only moves from the
previous `67.64%` to about `68.29%`, so phase `316` remains in progress. The
next execution wave still needs a materially larger denominator than the crates
covered so far if the phase is going to reach the required `80%+` floor.
