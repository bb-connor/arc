# Public authority enrollment and separate verifier custody

Build on the checkpoint artifact handoff with two sequential boundaries. Each
role generates and retains its own key. Public pins selected administratively
before agreement bind buyer, provider, verifier, checkpoint, status and governance.
Governance/status sign the existing execution context outside the provider. The
provider accepts that context only against its separate pins and own key, then
provisions native authority and funding policy without creating other role keys.
Exact completed bootstrap retries preserve the original policy and UUID; partial
or missing state fails closed and never silently regenerates an authority.

The verifier receives public artifacts rather than the provider's private journal
or capability token. Its enrollment pins the complete original policy and signed
agreement. Its request carries the signed submission, execution bundle, original
and submitted outputs, input bytes and original prepared claim transaction. The
verifier independently queries its configured observer for that transaction and
validates inclusion, domain, allocation, claim commitment and resolution window.
An observation supplied by the provider request is never financial authority.

Reuse the same actual Finding assessment and pinned Python W0 checker for local
and separate verifier decisions. Factor pure artifact checks from journal lookup;
native paths retain full original request/preimage checks. The public verifier
authenticates the native request commitment and action input through original
signatures, without claiming full private source replay or waiver authority.
Its decision uses the existing registered v2 envelope and original claim IDs.

The verifier stores the first request and decision durably before publication in
its own explicitly initialized SQLite custody. Exact replay uses original
assessment time, observation and response bytes, without private keys or a live
observer. Fresh invalid/unavailable authority never becomes either financial
decision. Signed negative decisions require valid execution authority and an
actually checked incorrect output. The provider verifies and retains imported
decisions against its original journal and observed claim; an external handoff
cannot fall back to local signing.

Use bounded canonical file commands and the existing owned local observer socket
for process reproduction. Transport hosting and independently administered real
organizations remain separate gates. All private keys stay in their originating
role directories, while public files cross the process boundary. One allocation
per authority/log remains the capacity limit. Local operator/verifier journals
have no external rollback anchor and standing has no external revocation feed.

Tests cover role aliases, signed context replacement, partial bootstrap, key
rotation/loss, original identity replay, foreign claim observations, canonical
ingress, conflicting decisions, unavailable checkers, response publication loss,
real payout/refund and Python public witness verification. Existing custody,
financial resolution and earned-child recovery remain regression gates. Work and
review proceed inline without sub-agents in the existing isolated worktree.
