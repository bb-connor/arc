# Independent receiver trial package

This is the implementation target for the outside operator requested by the
project owner. No outside operator has participated yet. The local evolving-work
executable is a reference trajectory, not evidence of independent administration.

## Target

A buyer runs an OpenAPI authentication review. Its first result identifies an
operation with no required authentication. Only then does it select an already
enrolled specialist, allocate the specialist's work, fund it, and extend the
running graph. The intermediary's native invocation uses that specialist. The
specialist earns an observed escrow claim before the intermediary is killed.
The original claim remains collectable after the intermediary's refund.

Discovery here is selection from owner-approved readers. It does not authorize
disclosure to an arbitrary unregistered peer. Enrollment creates keys and
policy; it does not pre-create the specialist's task, capability, agreement or
deposit. The local graph has one protected writer. Receiver replicas hold that
writer's exact lineage; this is not a consensus protocol between replicas.

## Public inputs and the receiver boundary

The retained trajectory exports `publicArtifacts`:

| Input | Owner and validation |
| --- | --- |
| `initialGraph`, `extendedGraph` | Existing S1 signed graph, allocation pool, witnesses, routes, revocation epoch and single-use continuations; the owner installs additive growth by expected-parent digest |
| Role `request` | Existing native `ToolCallRequest`; receiver-issued capability, exact tool arguments, governed intent and federated origin |
| `context.chioDelegation` | Existing D1 v2 signed permit and slot ID; input commitment covers **all** tool arguments |
| `context.chioSwarm` | Existing artifact IDs and SHA-256 digests; resolve exact graph history from the receiver's protected store |
| `context.chioTreaty`, `context.chioAdmission` | Existing bilateral treaty/DSSE and admission references; resolve from owner-provisioned records |
| Role `agreement` | Existing bilateral native-funded v2 agreement; canonical hash of the **entire** final request, receiver authority UUID, checker context and settlement domain |
| Role `receiverPackage` | Public deployment policy, exact admission bundle and treaty artifact records used by the reference receiver |

All hashes use their existing definitions. In particular D1's domain-separated
`binding_digest` is distinct from ordinary SHA-256 over canonical JSON. The EVM
allocation ID uses the existing chain/escrow/terms ABI derivation. Implementers
must not substitute one hash domain for another merely because both produce
32 bytes. The funded agreement commits to the request containing the D1/S1
references; those references do not contain the funded agreement hash, so the
binding has no hash cycle.

The exported policy describes the reference owner's enrollment. A new receiver
creates its own policy, key, capability and custody identity, then negotiates
new terms bound to those values. Importing public keys from a request is not
enrollment. Funding alone cannot grant tool access. The local fixture's treaty
antecedents are signed permission statements, not proof of completed work;
completed-work evidence comes from the native outcome and F1 execution bundle.

## Required implementation exercise

Implement the receiving boundary in a separate repository without importing
the Chio Rust kernel. Use the existing W0 checker and existing escrow unchanged.
Before implementation, freeze the public interface, threat cases and held-out
task generator. Keep the operator's keys and durable stores under that
operator's administration. Record every clarification and source change needed
to make the receiver interoperate; do not repair incompatibilities invisibly in
the reference side.

An admitted invocation must bind one receiver, subject, capability, input,
request, delegated slot, graph task/allocation and escrow allocation. Missing
treaty, altered input, foreign receiver, duplicate financial allocation,
re-signed consumed continuation and uncertain original dispatch must not create
a new effect or payment. Repeat exact recovery after the prescribed process
loss. Retain signed public artifacts, physical invocation counts, original
operation/claim identity and settlement transaction inventory.

Never publish operator seeds or authority databases. Use exported public
artifacts and separately reviewed observations. The reference CLI creates
private disposable state that contains signing material and is unsuitable for
distribution in its entirety.

## Matched conventional construction

Give the comparison receiver the same capability scopes, bilateral consent,
checker, escrow contract, signatures, persistent request IDs, recovery rules and
failure schedule. It may use a well-designed transaction journal and standard
capability/delegation libraries. The hypothesis is reduced work needed to add
and compose a receiver, not that conventional software cannot conserve money.

Record implementation and integration hours, total changed source, pair-specific
adapters, interface changes, unresolved semantics and recovery interventions.
For each held-out task, record checker-accepted useful output, wrong or missing
output, compute/checker/rail costs, failed-attempt expense, time with capital
locked, and obligations remaining after failure. Count unsuccessful attempts
and unavailable results. Publish the input set and stopping rule in advance.

The hypothesis is weakened or falsified if the Chio path needs comparable
bespoke pairwise code, or if its apparent useful-work gain disappears after
checker costs, failures and locked backing are included. A local successful
trace cannot answer that comparison.

## Execution evidence and delivery

The local fixture injects an existing in-process co-signer during fresh work.
There is no independently administered signing service in this result. The
pre-settlement execution receipt is signed by the original receiver, after
revalidation of its frozen bilateral admission provenance. It asserts local
execution and binds the exact request and output; it is not a final bilateral
delivery receipt. The first child collection report records that remote
co-signing was unavailable after the parent was lost. Both collection reports
remain in the trajectory. Their payment transaction, native operation and
physical continuation identities are unchanged.

An outside receiver must preserve this distinction. A final co-signed receipt
transport can be evaluated separately, but it must not become a new parent veto
over a claim already earned under the immutable agreement and escrow rules.
