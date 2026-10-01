# Product authority readers

Scope: the next 28 raw-input baseline files in CLI (13), API-protect (6), and
proof-room (9). Implement inline under the existing execution authorization.
Preserve original signed bytes, numeric contracts, and fail-closed decisions.

1. API-protect: bound and validate original JSON before projection, preserve
   local parser causes with redacted external errors, remove unused permissive
   nonce middleware, and check clock, expiry, and request-reservation ownership.
2. CLI: review all 13 readers, repair original-byte boundaries and classifier
   ambiguity, and retain strict receipt and proof verification semantics.
3. Proof-room: bound artifact reads, reject ambiguous JSON before projection,
   bind successful verification to the returned/report identity, and distinguish
   embedded fixture construction from installed/untrusted inputs.
4. Record semantic inventory dispositions and negative controls; run focused
   package and inventory checks, review the complete diff once, and commit the
   finished batch locally. Hosted qualification and M5 remain separate gates.

Validation targets: duplicate and oversized inputs, typed local rejection causes,
safe public errors, time/expiry overflow and rollback, replay-window capacity,
proof/report identity substitution, plus existing tests for the changed owners.

No push, merge, release, or external activation is part of this batch.

## Execution review (October 1, 2026)

Reviewed at `a2630c20a1` in the [product, CLI and provider readers review](../../reviews/2026-10-01-execution-review-product-cli-provider-readers.md). The cross-cutting verdict is in the [pass 9 execution review](../../reviews/2026-10-01-execution-review.md).

**Verdict:** Done, with defects. The proof-room verified bundle type is sealed correctly and the replay readers bound each line before allocation.

Open findings against this plan:

- **PR2, Medium.** Every API-protect sidecar handler moved to `decode_signed`, so a Python SDK request carrying `0.00001` arrives as `1e-05` and is refused with 400. Independently verified.
- **PR3, Medium.** The new shared clock refuses to run while the wall clock is behind its last reading, so an NTP step back is an outage for its duration.
- **PR10, Low.** The worker-response reader is recorded as bounded, but a 16 MiB nested file can make it allocate about 1 GiB.

**Next:** Decode sidecar envelopes with ordinary numbers (PR2) and let the clock tolerate a bounded step back (PR3).
