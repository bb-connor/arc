# P2 operating contract

P2 provides advisory explanations for the P1 sequential native support-ticket
profile. It adds no execution right, native participant, workflow mutation,
provider consult or general semantic remedy. P3 supplies transformation,
prerequisite and endorsement enforcement. The pure registry can describe those
alternatives now, under explicitly supplied observations. Integrity provenance
never substitutes for scoped endorsement: `requires_integrity` yields
`NeedsFreshEvidence` until the corresponding P3 contract exists.

## Composition and trust

Construct `RecoveryExplanationService` with the selected recovery scope, an
operator-selected advisory trust domain and issuer, a separate Ed25519 advisory
signer and validated limits. It can construct classified reports from explicit
facts without a kernel, process, provider, disclosure issuer or budget mutator.
The native adapter refuses reuse of the disclosure signer. Signing takes place
outside store transactions and intake locks. The pure crate cannot sign and
has no effect/runtime/clock/filesystem/network dependency or port.

Mount `recovery_explanation_router(runtime, service)` on the authenticated private
control listener alongside the P1 router. `POST /v1/recovery/explain` accepts only
the canonical closed `{capability, workflow_id}` transport. The capability string
is at most 32 KiB. The existing `Inspect` permission supplies current scoped
control; there is no new permission or change to a P1 deployment identity.
The existing P1 protected-read port also requires clearance for the retained
source. Actors below that clearance receive a generic forbidden response before
any graph is loaded. This phase preserves that boundary. Pure projection supplies
signed restricted views when the trusted host already holds a separately
mediated basis or current source exceeds an authorized retained basis.
Original token liveness is observed through the kernel's current verifier,
including revocation, time and delegation. No invocation budget is consumed.

The endpoint returns only `SignedRecoveryExplanationViewV1`. The Rust inspector
API separately authenticates current clearance for the joined full graph before
returning `ProtectedRecoveryExplanationV1`. This object has redacted diagnostics
and no public serde representation. The trusted explicit-data service API assumes
its caller already holds its supplied inputs; it is not an unauthenticated
network inspector. The native actor principal must fit the closed ASCII ActorId
profile (at most 128 bytes), or the explanation profile refuses.

The CLI uses `chio recovery explain --endpoint ... --capability ...
--workflow-id ...`. Python and TypeScript use `RecoveryClient.explain(...)`.
They make one bounded request without redirects or retries. Their wire-shape
validation does not select a trusted signer, recompute an inaccessible basis,
or grant permission. Trusted inspector tooling must call
`verify_explanation_report` with independently selected key, domain, issuer,
scope, deployment/policy/contract/intent roots, limits and original authorized
inputs. `verify_explanation_view` checks selected projection provenance and
recipient only; it does not claim full report recomputation.

## Observation and disclosure

A snapshot retains each source's version, validity interval, object, provenance,
label and explicit gaps. The native source generation and retained workflow
revision are independent observations, not one atomic global read point.
Policy eligibility includes current workflow control and admission closure.
Cancellation cannot look feasible. Stale source generation or expired original
requirements yields fresh-evidence advice, not a renewed frozen action.

P1's destination fact describes the pinned operator recipient and effect
contract. It asserts no newly consulted remote provider ACL. A changed selected
policy or recipient invalidates the native deployment/basis and refuses live
resume. The pure inputs can describe separately versioned provider ACL facts,
but mutable provider consults and enforcement need their own qualified contract.
In-flight and unknown operations remain bound to their original reconciliation;
completed or partially spent effects never become replacement sends.

Context classification covers intent, status, policy and influence. Each fact,
candidate and disclosure constraint has its own label. Full graph classification
joins every such input, including costs and estimates via template classification.
The registry's aggregate label protects the full graph; candidate visibility
uses individual labels. An inaccessible candidate is filtered before search or
ranking. Its presence, count, costs, truth value or deadline cannot change a
public result or cause public search exhaustion. Secret disclosure constraints
also exclude an alternative from public ranking.

Restricted views have a fixed public window bounded by the requesting control
capability; hidden evidence deadlines do not shorten it. Full reports bind all
classified commitments. Public views carry no snapshot, intent, registry,
evaluation or full-report digest/signature. References contain 256 random bits,
are bound into the signed recipient view, and supply neither lookup nor bearer
permission. No public graph-reference resolver is introduced. Dictionary probes
cannot compare a secret digest that is absent from the response. HTTP exposes
request completion and generic success/refusal categories on the private listener;
this is not a constant-time claim about storage, signing or arbitrary providers.

## Resource, persistence and compatibility limits

There are 32 facts, 16 templates, eight explicit dependencies per template and
16 returned alternatives. The planner has no recursive synthesis. It uses a
partial order over compatible task family, authority and audience constraints,
approvals, effects, budget estimates and declared latency. Distinct audiences
with equivalent labels remain alternatives. Unspecified latency is incomparable.
Search truncation is `SearchBoundReached`, never a claim that no remedy exists.

A request's full and projected evaluations share a fixed work ceiling of 4096,
allocated equally. Membership visits, fact checks and dominance comparisons are
charged. Joining or search exhaustion is conservative. Work units describe
planner operations, not wall-clock cycles or signature verification. Wire ingress
retains 64 KiB, depth 16, 4096 JSON nodes and 32 KiB aggregate string ceilings.
Output transport is capped at 256 KiB; signing canonicalizes closed payloads.
Validity is at most 30 seconds. Current visible fact deadlines further constrain
visible views, and all relevant fact deadlines constrain protected reports.

HTTP has two independent explanation slots and no unbounded blocking queue.
Each authenticated actor has 32 probes per 60-second fixed window. The service
retains at most 64 actor identities for its lifetime without eviction. Exhaustion,
clock rollback, poisoned locks and entropy failure refuse generically. This is
process-local abuse/load control, not durable authority; restart creates a new
intake window. Deployments must retain their existing private-listener controls.
No report graph or reference is persisted, and no P1 store migration is needed.

New schema IDs use `https://chio.computer/schemas/`. Existing schema identities,
P1 grants, signed coverage, request custody and native admission remain unchanged.
All references resolve through the finite local schema catalog; the URLs do not
cause website requests. Upgrades cannot reinterpret reports as grants.

## Evidence boundary

Local acceptance covers the supported native profile, pure/differential leak
corpus, report recomputation, correctly re-signed tampering, closed wire vectors,
CLI/SDK transport, strict owning-crate review and portable builds. Cached Vitest
4.1.8 and esbuild 0.27.7 differ from locked 4.1.11 and 0.28.1; TypeScript is pinned
5.7.3. No pins were changed. Hosted CI, lock-exact JavaScript installation, live
external provider delivery, deployment, scale qualification and independent human
review remain separate. Prior P1 environment limitations remain documented in
its verification record, including socket/DNS restrictions and unavailable Kani
launch. This phase claims no new formal proof or public production deployment.

The broader P1 runs during P2 were not wholly green: an initial parallel run
passed 12 tests and failed four; a serialized run passed 14 and failed two.
The failures included conservative native admission refusals and a crash child
that did not reach its requested cutpoint. A later focused serialized run passed
all 15 non-parent regression tests. The serialized parent completed 26 cutpoints;
the remaining `return-recorded-revoked` cutpoint passed separately with one actual
effect before and after recovery. This establishes successful coverage of all
27 cases across the retained runs, not a single successful full stress run or a
proven diagnosis of the earlier failures. No assertion, deadline or native
authority check was weakened. The broader Node HTTP suite passed 37 tests and
failed 41 socket-dependent tests with sandbox `listen EPERM`; the focused
recovery conformance/client corpus passed 201 tests without listeners.

From the repository root, run
`python3 docs/architecture/recoverable-agent-runtime/implementation/p2/evidence/verify-package.py`
to check the retained source, archives, evidence hashes, coverage and unchanged
dependency pins. This [package auditor](evidence/verify-package.py) does not rerun
the implementation tests or establish production qualification.
