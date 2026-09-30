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
