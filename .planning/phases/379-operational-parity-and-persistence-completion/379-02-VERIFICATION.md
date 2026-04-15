# Phase 379-02 Verification

Plan `379-02` satisfies `OPER-02`.

## What Landed

- `crates/arc-tower/src/service.rs` now buffers the live request body once,
  computes `body_hash` and `body_length` from those exact bytes, passes them
  into `EvaluationInput`, and rebuilds the forwarded request body from the same
  bytes before calling the inner service.
- `crates/arc-tower/src/evaluator.rs` already binds `body_hash` and
  `body_length` into `ArcHttpRequest`, so the signed receipt content hash now
  reflects live request bodies instead of always seeing `None` / `0`.
- `crates/arc-tower/tests/axum_integration.rs` proves the real Axum runtime
  path: a POST body survives ARC evaluation and reaches the handler unchanged.
- `crates/arc-tower/src/lib.rs` and
  `crates/arc-tower/tests/tonic_integration.rs` now narrow the claim
  truthfully: bytes-backed Tower/HTTP2 traffic is covered, but real
  `tonic::body::Body` replay remains follow-on work and is not claimed as part
  of this closeout.

## Validation

Passed:

- `cargo test -p arc-tower`

## Verdict

`OPER-02` is complete. The shipped `arc-tower` middleware no longer evaluates
live request bodies as `None` / `0`; it binds real raw bytes into evaluation on
the supported replayable body path and preserves those same bytes for the inner
service.

Phase `379` is still not complete overall because `OPER-03` remains pending.
