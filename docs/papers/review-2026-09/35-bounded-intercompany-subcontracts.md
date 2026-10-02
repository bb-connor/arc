# Bounded work through a provider and its specialist

A buyer, provider and specialist now complete a checked subcontract through
separate kernel authority, agent identities, disclosure rules and local payment
journals. The provider's isolated Python worker buys real work from the
specialist's Rust kernel. The original buyer verifies both deliveries using
independent Python and Rust implementations. Recovery preserves the distinction
between a failed parent delivery and an already completed child expense.

This is the direction I would choose for Chio: a common work contract through
which organizations' agents procure, delegate, verify and settle work while
each organization retains its own authority. It builds on the cognition-market
infrastructure already present. It is still not an established breakthrough.
The strongest objection is that the result composes familiar authorization,
signatures and durable accounting into one narrow application under one
operator. Independently operated companies completing useful work through
independent implementations, with materially less custom integration and
recovery effort than an equally provisioned alternative, would change that
judgment. Neither more signatures nor more local test cases alone establishes it.

## The escape that changed the design

The first three-party prototype withheld B's kernel key from its worker and
limited the worker's network connection to C. It still gave the delegated agent
enough authority to buy another job. An adversarial client with only that agent
key and public C enrollment changed the job id and completed another specialist
review for 100 TST. The separately verified public delivery and pre-permit
binary hash are retained in this report's evidence. The historical binary is
not packaged as a reproducible source build.

A readonly agreement file or fixed network destination does not constrain what
a compromised agent can ask that destination to do. The receiver must enforce
the procurement boundary. C now requires a B-kernel-signed permit for the exact
child agreement, parent agreement and parent request, delegated agent,
specialist, 100 TST ceiling and expiry. B signs it inside the authorized parent
dispatch. The worker receives that permit, never the signing key.

Thirteen native receiver attacks deny extra jobs with and without the permit,
an original job without its permit, changed input, price, expiry and onward
delegation, agent-forged and differently signed permits, parent substitution,
duplicate work, expanded input and capability issuance by the permit promisor.
A valid quote replay returns the original consumed capability. C retains one
job, one review and one captured charge. These checks bypass the cooperative
Python client's preflight and verify the actual C-signed denial receipts.

## Four identities and local authority

The three parties use four distinct keys: A's buyer agent, B's kernel, B's
delegated agent and C's kernel. B issues A's capability; C issues the delegated
agent's capability. C's configured B promisor is a procurement predicate key,
not an issuer root. A valid B-signed replacement capability is rejected by C.
No request, report, enrollment or subcontract can activate a new issuer root.

Parent work profile v4 adds one closed subcontract policy to the v3 agreement.
It names the selected specialist, delegated agent, approved paths, exact
projected-input hash and a 100 TST child ceiling no higher than the parent's.
The child retains the existing v3 contract with no onward subcontract. Its job
id derives from the complete parent agreement, preventing an agent from
inventing additional jobs under the same permit.

B's host configuration selects C's identity, HTTPS origin, signed enrollment,
delegated key and readonly worker code. C independently configures B's promisor
and agent. Enrollment v3 advertises supported profiles and C's selected
promisor, with the same five proof-of-possession session grants. Older
enrollment profiles remain verifiable. B advertises subcontract support only
when its configuration loads and C's enrollment names B's actual kernel.

## Disclosure, isolation and evidence

The provider reconstructs a minimal OpenAPI document containing only approved
paths' effective authentication declarations and referenced scheme fields.
It discards metadata, descriptions, responses, examples, extensions and
unselected paths, including private fields beneath an approved operation.
Independent Rust and Python projections must match the buyer-approved UTF-8
digest. The child checks the same bounded authentication profile as before;
this does not assess a deployed API or arbitrary source correctness.

A synthetic private canary appears in both root metadata and a selected
operation's description. It is absent from the child package, worker input and
C's retained request. Missing subcontract permission, a different specialist
or delegated agent, unavailable local activation and a changed disclosure
digest deny before any child state or specialist work is created.

B runs the procurement worker in a nested bubblewrap mount and network
namespace. The only network path is an AF_UNIX tunnel to the locally selected
C endpoint, over which Python still verifies TLS 1.3 and hostname. Readonly
mounts contain its distinct agent key, input, contract, permit and connection.
The parent state and kernel key are absent. A malicious replacement worker
cannot read the parent key or open direct TCP, and its attempted extra purchase
through the allowed tunnel receives a C-signed denial.

The malicious worker also plants a symlink from a diagnostic filename to the
parent kernel seed. Host writes stage outside the worker mount and atomically
replace the destination entry. The probe completes without changing the parent
key. Coordination locks likewise remain outside the writable worker mount.
The operating system, configured host runtime and receiver implementations
remain trusted; this does not protect against a malicious company administrator.

B's signed report includes C's public request and delivery. The native B output
guard and both verifiers check the derived child agreement and disclosure,
parent-bound permit, signed market artifacts, checked report, Finding, native
receipt and Merkle inclusion. Twelve malformed nested reports have valid outer
B signatures and still fail both implementations. They include missing or
additional child fields, different work, forged child evidence and correctly
re-signed but invalid procurement terms. A live B output-guard test changes
only the child's signature, leaving the parent check correct, and obtains a
durable zero-charge parent rejection.

## Recovery is separate for each purchase

| Failure boundary | Parent result | Child result | Final A expense | Final B child expense |
| --- | --- | --- | --- | --- |
| No failure | Verified delivery | Verified delivery | 100 | 100 |
| B dies after C's delivery | Unknown, payment released by agreement | Verified delivery | 0 | 100 |
| B returns invalid child evidence | Checked-output rejection | Verified delivery | 0 | 100 |
| C dies after capture, before response | Checked-output rejection | Delivery recovered from C | 0 | 100 |
| C dies before or after its review write | Checked-output rejection | Unknown, payment released by agreement | 0 | 0 |
| Both die after C's review write | Unknown, payment released by agreement | Unknown, payment released by agreement | 0 | 0 |

All amounts are provider-local TST credits. Each child has its own bounded
buyer journal; this is not a shared company wallet, distributed atomic
settlement, external funding or a solvency claim.

The new local `subcontract-recover` operator command validates the retained
permit and selected relationship, then runs the isolated buyer's existing
recovery. It issues no new permit and never reruns the parent. Four concurrent
parent recoveries and four concurrent child recoveries converge in each
failure scenario. The completed child expense is recorded once, or its signed
incident remains unknown. Optional child release uses the existing native
co-signed release protocol, with the original operation and physical payment
journal unchanged. A's original parent package also replays offline.

## Qualification and current scope

The [manifest](evidence/35-bounded-intercompany-subcontracts/manifest.json)
records the final binary, source inventory, public artifacts and logs from
this uncommitted checkout. All 234 artifacts from report 34 remain byte-for-byte
intact. No commit, remote CI, merge, deployment or release is claimed.

Ten new three-party process scenarios pass. The prior 19 HTTPS, 18 legacy HTTP
and seven mutually agreed release scenarios also pass against the same final
binary, for 54 process scenarios. Eleven Rust example tests and 30 Python tests
pass. Example Clippy with warnings denied, root and example formatting, and
diff checks pass. The paper builds at 12 pages and 4,937 body words. Existing
native kernel and store source files are unchanged from report 34; their older
unit-test logs are historical evidence, not newly rerun tests in this report.

The [wire and operator notes](../../../examples/federated-work/SUBCONTRACT.md)
describe local activation, disclosure, authority and recovery. One Linux host
and one operator still control every fixture. There is no independent-company
trial, cross-border deployment, external settlement, live language-model task
selection or general-purpose subcontract implementation. The disclosure profile
does not determine whether the approved path names themselves are confidential.

## What this adds relative to existing work

AP2 already uses signed mandates and deterministic verification. Its v0.2
specification explicitly leaves agent-to-agent mandate delegation outside its
current scope. That is a scope boundary, not evidence that its mechanisms cannot
implement this contract. [AP2 specification](https://ap2-protocol.org/ap2/specification/)

A2A supplies the communication interface used here; authorization and the
credential lifecycle require surrounding systems. The experiment connects that
interface to existing Chio market, kernel, artifact and recovery machinery.
It does not infer an impossibility result from A2A's different responsibilities.
[A2A specification](https://a2a-protocol.org/latest/specification/)

The next substantial test is independently operated, useful work through this
contract, with measured integration and recovery costs. Another local profile
alone would not answer the question the handoff asks.
