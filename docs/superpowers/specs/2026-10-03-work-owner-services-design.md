# Work across independently controlled owners

Status: proposed. Implements AW06 through AW10 and AW15.
Parent: [architecture and constraints](2026-10-03-agentic-work-kernel-design.md).
Consumes: [work runtime contract](2026-10-03-work-runtime-design.md).

## Boundary

Run an owner-scoped work service inside existing chio-control-plane hosting. Use the hardened ingress, TLS/peer authentication, configured trust and serving authority supplied by the security lane. Do not deploy the example's tiny_http listener as a production service.

A peer can request work, query its permitted evidence and request exact co-signing. It cannot provision a trust root, choose a signer, activate a runtime replay source, select a rail endpoint, replace policy or install a graph authority.

Owner setup is a privileged local operation. An activated domain binds kernel identity, serving-store identity, program/allocator/witness scope, accepted peers, treaty policy, registered tools, recovery profile and rail configuration. Starting with a wrong/missing store or changed identity fails closed.

## Service operations

Use one versioned chio.work.v1 contract over:

- POST /v1/work/prepare: WorkPreparationV1 -> WorkPreparedV1, under the configured local authoring role
- POST /v1/work/commands: WorkCommandV1 -> WorkCommandResultV1
- POST /v1/work/query: WorkHandleV1 -> authorized WorkViewV1
- POST /v1/work/cosign: closed receipt or bilateral-DSSE request -> exact response
- authenticated negotiation of supported profile/features, with no mutation

Use request bodies for scoped references rather than placing protected identifiers in URL logs. Local credentials may be used on the private worker socket; remote requests require the security lane's verified caller and configured peer binding. TLS server identity and work principal authorization are distinct checks.

The existing D1 offer and capability issuance happen at the receiver. Selection binds the returned receiver-signed offer and exact capability/request. Agreement acceptance uses locally authorized signers, with both signatures over the same complete body. No provider selection helper has both owners' private keys.

Unknown peers remain unauthorized until owner enrollment. Discovery may suggest a provider; it does not create trust or data-reader authorization.

## Peer transport and evidence delivery

Implement BilateralCoSigningProtocol using configured peer endpoints and the hardened HTTP/egress machinery. Reuse chio-federation's canonical receipt and DSSE reconstruction. A remote request must authenticate the expected peer, reconstruct the signing body, verify its signature, check the retained local invocation/treaty context and audience, and only then request the local signing authority.

The signer endpoint is not a generic arbitrary-byte signing RPC. Raw PAE and the supplied signature alone are insufficient if they are unbound to locally accepted work.

Persist the exact bilateral-delivery intent through existing receipt/native reconciliation ownership. Retry only that statement and signing context. Missing peer receipt never causes another tool dispatch or a second payment. Report local execution and pending bilateral completion separately. If current native reconciliation does not expose the required idempotent operation, add a narrow owner-scoped port through the security/recovery lane rather than another general recovery loop.

Prototype peer_https.rs and peer_client.rs supply useful framing/authentication cases. Their verifier-specific endpoint is not already the full work service.

## Funded and unpaid profiles

Unpaid work uses the same work commitment and native checks without a financial reference. Funded work binds an exact signed agreement, configured rail, verified deposited reserve, native authorization/hold and verifier decision.

Move chain/ABI/terms verification from the standalone example into chio-settle::work_claims under its existing web3 feature. Keep native PaymentAdapter wiring in chio-control-plane::work::funding. This avoids a chio-kernel -> chio-settle -> chio-kernel dependency cycle. Retain journal ownership in the existing serving/financial stores; do not copy the example's loosely coupled Journal into a second execution authority.

The economic contract remains the existing F1 construction. Lift W0's fixed server, price 100, XTS mapping and fixture checker into explicit validated profile fields. A profile identifies asset/network/contract, integer units, acceptance verifier, custody rule, deadlines, finality and the supported recovery behavior. Observations are verified against that configuration; a caller cannot submit their own reserve attestation as authoritative.

For the initial local-devnet profile, adapt the existing WorkClaimEscrow contract and transaction recovery. Do not change its financial state machine merely to promote packaging. Native settlement and chain settlement retain distinct original references. A child has its own actual funding; unused parent allowance is not money. Payable work remains payable after parent failure/refund. Public-money operation stays unsupported until separately qualified.

## Recovery seam

The recovery agent owns exact reviewed continuation allocation, native effect observation, protected artifact references and confined release. The work layer calls those APIs.

A legitimate changed request after denial uses a recovery-approved new continuation and explicit relationship to the original work. It must not mutate the original sealed selection or pretend the changed request has the original D1 binding. Until the current D1/S1 profile has an explicitly authorized way to allocate and link that continuation, return a typed unsupported binding result. Do not loosen D1 to make a demo succeed. Beta acceptance includes one supported fresh-child allocation path within existing authority/budget, linked to the recovery continuation.

After caller expiry or cancellation, scoped historical settlement can advance an already owned obligation. It cannot trigger a new tool call or disclose retained output. Current release authority is checked separately. Effect state remains unknown if the native authority cannot resolve it.

## Acceptance topology

Three owners use separate processes, protected state directories, keys and configured peer identities. A local multi-process deployment establishes process and credential separation, not independent administration. It must be installable on separate hosts without shared directories or fixture key access.

Exercise authenticated useful work, refusal by an owner, wrong peer/audience, late/stale request, dropped response, caller cancellation, remote co-signer outage, restart and child claim collection. Observe actual effects and state, not HTTP success alone.

Deliver an external operator package with private-key generation on each owner's host. The owner has no outside partner yet; mark outside operation pending. Never synthesize an independent-operator result from multiple keys on one administrator's host.
