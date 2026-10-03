# Independent inbound-authority review

Reviewer: `inbound_authority_final_review`, fresh context, read-only. Candidate:
working diff based on `e84e53ae436ed8d8e2e5b85e62dea185cf7c33d6`.

**Original verdict: changes requested. Two Important findings; no Critical or
Minor finding identified.** No Cargo commands or repository mutations performed.

1. **Important: production clients cannot possess proof-required subject keys.**
   `cmd_run`, `cmd_mcp_serve` and the remote session factory mint to host-owned
   fresh or federation-derived keys and give clients only public capabilities.
   Invocation proofs require that exact subject. Fixtures retaining their own
   signing keys miss this bootstrap gap. Preserve authenticated `cnf.chioSenderKey`
   through remote issuance/resume and provide operator-bound native/stdio client
   public-key configuration.
2. **Important: authorization occurs before downstream URL normalization.**
   With registered readable `/safe/{id}/{tail}`, raw `/safe/%2e%2e/admin` matches
   the template, then reqwest removes the parent segment and forwards `/admin`.
   Unknown-route denial and the receipt describe a different operation. Reject
   normalization differences before authorization and prove zero upstream calls.

Other inspected paths were internally consistent: socket plus credential proxy
trust; JWT/introspection/local OAuth context; closed confirmation decoding;
nested dispatch/replay reservation; non-consuming preview; original threshold
parsing behind control authentication.

## Declined to judge

- Compilation, tests, lint, generated bindings and inventories: author owns gates.
- Restart-safe/distributed replay: default store is explicitly volatile.
- TLS and deployed proxy sanitation: AP7 and operator responsibility.
- Unbound bearer grants and separate restricted session credentials: compatibility
  authority, not evidence for proof-required invocation.
- Origin-specific proof policy and required-proof HTTP projection: explicitly
  refused, not supported consumers.
- Hosted qualification, publication and deployment: separate evidence required.

## Author disposition

Both Important findings accepted for the single corrections pass. Reproducing
controls and final verification are retained with the execution evidence. The
original negative verdict remains; no second independent review is claimed.
All declined boundaries remain explicit in the handoff. No Minor item is deferred.
