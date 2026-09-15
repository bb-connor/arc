# Verifiable uncertain work across organizations

The checked-work protocol can now carry a native unresolved incident from the
Rust provider to the Python buyer and to either public verifier. Previously,
the provider's durable kernel retained an unknown execution and an authorized
payment hold, but its delivery interface returned only an error. The buyer now
receives evidence bound to its exact accepted request, retains it durably and
can retrieve it offline. Its reservation remains held.

This is progress toward agents working between companies. It does not establish
a breakthrough. The strongest objection is that it is an application-specific
integration of familiar durable execution and signed evidence, still developed
and operated by one project. Independently operated implementations completing
useful work and resolving failures, with a measured reduction in bespoke logic
against a matched alternative, would change that assessment more than another
local mechanism alone.

## The business boundary

The distinction is between retrieving evidence and finishing a job. A verified
incident produces `incidentVerified: true`, `buyerVerified: false`,
`workExecuted: null`, `localCreditSettled: false`, and
`paymentResolution: "required"`. The command can successfully retrieve this
status without claiming successful work. No expense, reservation restoration,
paid receipt, zero-charge receipt or Finding is manufactured.

| Failure | Retained native outcome | Buyer action |
| --- | --- | --- |
| Buyer dies before the actual send | No matching provider incident | Preserve uncertain attempt and reservation; no automatic resend |
| Provider dies after dispatch commitment, before its review write | Signed unknown incident; one consumed invocation and authorized hold | Verify and retain the incident; keep 100 units reserved |
| Provider dies after its review write, before kernel return capture | The same unknown terminal class and hold | Verify and retain the incident; keep 100 units reserved |
| Buyer dies after checking the incident, before retaining it | Provider's original incident remains available | Retrieve again and atomically retain one incident |

The before-write case records zero reviews; the after-write case records one.
Their shared unknown terminal cannot establish which effect occurred. The
process harness observes those tool records as test evidence, while the public
buyer correctly reports unknown execution in both cases.

## Native implementation and a verifier defect

`SqliteAdmissionOperationStore::export_outcome_unknown_projection` reads the
qualified authority store, verifies the retained operation, projection and
participants, reconstructs the deterministic dispatch predecessor, and requires
exact replay of the stored projection. It signs the existing
`SignedAdmissionTerminalProjectionV1`. The read neither claims recovery nor
mutates an operation, budget or payment journal. A temporary-fixture test checks
that ordinary SQL cannot update the immutable projection, then deliberately
removes that fixture's trigger and corrupts storage to verify read-time rejection.

Inspection found that the remote terminal verifier checked signatures,
manifest hashes, operation succession and the incident record kind without
fully binding the incident's contents and replay id to that dispatch. A valid
signature over a self-consistent but substituted incident was insufficient.
The verifier now decodes the closed incident shape, validates its exact
operation/context binding, compares the record's canonical contents with the
projection, binds the terminal incident id and rejects incompatible sidecars.
Four native substitutions test these checks after updating commitments and
signing again. Existing supported incident records remain valid; the native
verifier does not impose the example's narrower deterministic identifier profile
on every historical incident.

The example's read-only locator is bounded to a 4,096-operation store and one
unknown terminal for the negotiated work capability. Its raw query only finds
an id; the qualified store re-reads authoritative evidence before signing.
Delivery works even if the tool never wrote its local report. The capability
and accepted agreement are checked locally, and the buyer additionally binds
the native action hash to its exact retained request.

The Python implementation independently checks the native signature domain,
canonical embedded JSON, namespace, request-binding, operation, incident and
manifest hashes, retained dispatch and fences, capability digest, participant
set and exact terminal successor. It does not call the Rust verifier. The
harness runs the Rust verifier separately against the same public files.

The buyer adds an incident table separate from settled deliveries. A write
transaction requires the matching attempted request and reservation, enforces
a unique operation id and makes identical retention idempotent. Neither a
retained settlement nor a retained incident can be silently replaced by the
other through ordinary delivery processing. Local balances remain unsigned
observations, and the historical incident has no receipt-log inclusion claim.

## Qualification

The [manifest](evidence/33-verifiable-uncertain-work/manifest.json) records the
uncommitted source inventory, exact provider binary hash, public artifacts,
source snapshots and validation logs. The previous report's artifact hashes
are checked before export. No signing seeds, private TLS keys, role databases
or legacy bearer credentials are exported.

The final process run covers 19 HTTPS scenarios and 18 legacy HTTP scenarios
with the Python buyer. Three incident scenarios exercise both provider crash
positions and buyer crash recovery. Each uses four concurrent buyer processes,
checks one retained incident and no terminal accounting entry, compares the
original operation, payment journal and budget before and after retrieval,
restarts the provider again, and checks offline buyer replay. Each also rejects
ten malformed incident cases carrying valid provider signatures in both public
verifiers. These include substituted request bindings, dispatch fences, replay
ids, divergent record representations, payment capabilities, an invented Finding,
completed-state substitution, a boolean epoch, a changed signer and changed input.

The run retains the prior success, zero-charge rejection, payment-crash,
acceptance-crash, ambiguous-send, concurrency, Unicode and ingress checks. HTTPS
also retains its 13 enrollment and transport denials. Native admission tests
pass 72 cases; SQLite admission tests pass 85; the example passes six Rust unit
tests and 20 Python unit tests. Kernel/store and example Clippy checks pass with
warnings denied, formatting and diff checks pass, and the paper builds at
12 pages and 4,997 body words.

The [wire and operator notes](../../../examples/federated-work/INCIDENTS.md)
describe the result and offline verification commands. Only the Python buyer
adds incident retention; the original Rust buyer still fails unresolved `work`,
while its new public verifier accepts the incident profile. All process runs
remain on one Linux host, under one author and operator, using local test
credits. These results do not qualify power loss, hostile storage rollback,
external settlement, independent company adoption, release or remote CI.

## The unresolved settlement seam

This work deliberately preserves the original historical unknown. The native
store refuses recovery claims on terminal operations. It also validates an
unknown projection against an authorized, unmoved payment journal. A direct
rail release, a buyer-only balance restoration, or a late report inserted as an
observed kernel return would violate those boundaries.

A subsequent resolution needs its own locally activated authority, an exact
agreement/incident/hold binding, durable replay protection, an atomic budget and
settlement-intent transition, and recovery at the rail's idempotent operation
reference. The original projection must remain verifiable against the original
authorization even after a separately authorized resolution. Its history must
not be rewritten into a no-effect claim. Mutual consent to release a claim is
new authority, not new knowledge that the tool did nothing. This release path
is not implemented or claimed here.
