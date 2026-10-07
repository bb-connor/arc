# Authenticated verifier execution plan

1. Add failing boundary tests for provider signature, origin/enrollment binding,
   raw canonical ingress and receiver-owned read-only observation.
2. Implement signed request/export and bounded TLS service/client using existing
   dependencies and durable verifier custody. Expose explicit CLI commands.
3. Exercise real HTTPS payout/refund, malformed authentication/framing/TLS,
   unavailable receiver observation, response loss and keyless cached retry.
   Preserve original operation/hold, one execution and one financial outcome.
4. Review inline; run Rust tests, owned-chain tests, relevant Python/process
   regressions, strict Clippy, formatting and file hygiene. Record reproducible
   evidence, source/binary hashes and scope boundaries. Commit locally after
   checking the original checkout is unchanged.

User has authorized continued execution and explicitly prohibited subagents.

Implementation findings: retain the explicit `verifier-call` journal record;
add raw header/body bounds before the general HTTP parser; generate a proper
CA/server leaf for rustls; require error-specific negative evidence so transport
failures cannot hide observer/checker test failures. Historical exact journal
retries remain valid after a decision, while creation of a new call is excluded.
