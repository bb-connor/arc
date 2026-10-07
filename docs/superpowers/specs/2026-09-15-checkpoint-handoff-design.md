# Portable checkpoint operator handoff

The next bounded interoperability slice separates checkpoint signing from the
provider's native execution state. The existing single-allocation execution
profile and original agreement remain authoritative. This is a local artifact
interface for separately controlled custody, not proof of independent companies.

Use canonical request/response files and a separately initialized operator store.
An HTTP service would add transport and deployment assumptions before the custody
contract is qualified. Moving keys alone would leave the provider responsible for
signing; instead it exports a receipt and imports a verified public bundle.

The operator enrollment pins the complete pre-agreement context and native
authority UUID through an administrative input. A request contains a schema,
context digest and the original kernel receipt. It contains no private keys or
capability token; the receipt's action still discloses the W0 input. The existing
execution bundle is the response. Both ingress paths require bounded, exact
canonical typed JSON. These experimental example envelopes do not become new
registered protocol guarantees in this slice.

The provider retains an immutable handoff request before export. Once handed off,
ordinary evidence collection cannot fall back to local checkpoint keys. Import
checks the exact original native projection, request, output, agreement, pinned
checkpoint and status authorities, chronology, inclusion and standing. It retains
the first checkpoint before the bundle. Restart can finish this sequence with the
same response. Missing custody after Finding issuance fails closed.

The operator signs only the one receipt allowed by its enrolled log. It commits
the request and complete response in one SQLite FULL transaction before returning
bytes. An exact retry returns retained bytes without private key access; changed
requests cannot obtain another sequence-1 checkpoint. Missing state cannot be
recreated by signing. Changed keys cannot sign a fresh response. Original response
replay is historical and does not refresh standing or confer payment eligibility.
The operator's local store is a trusted custody boundary without an external
rollback anchor; copying or rolling back that store is not prevented here.

Verification includes signed adversaries, missing keys/state, conflicting retries,
canonical ingress, retained-custody loss, separate CLI processes, a Rust-native
execution to Finding/observed payout and refund, and the existing Python public
witness verifier. Existing local signing remains a fixture path unless a handoff
was retained. No kernel checkpoint same-signer rule is weakened. Provider,
checkpoint/status and verifier may still be administered by one local test owner.

Implementation proceeds under the standing instruction to execute next steps,
in the existing isolated integration worktree, with inline review and no agents.
