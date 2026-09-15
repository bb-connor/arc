# Breakthrough judgment

Review of `14-handoff-is-this-a-breakthrough.md`, 2026-09-13.
Repository commit `2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`, branch
`paper/roadmap-phase-0-1`. The twelve paper files already modified when this
review began were preserved. This judgment considers the handoff, the committed
implementation, and that working paper draft. It is not a release qualification.

**No: the evidence does not establish a Bitcoin-scale breakthrough in agentic
systems. It establishes a substantial implementation of receiver-controlled
authorization, durable execution, and signed evidence. The paper's argument
for a stronger conclusion still depends on restrictions it chose for its
alternative, and on treating a description of its own checker as a necessity
for other systems.**

This conclusion would remain if every implementation gap below were fixed.
The missing result is a demonstrated change in what can be built, what must be
trusted, or how much application-specific security work is required. Better
tests can establish that the mechanism works; they cannot establish that
mechanism's novelty by themselves.

**The central comparison still chooses its conclusion.**

The most consequential sentence is the assertion that every arriving value was
minted by the caller or its authorization server, making receiver-state checks
comparisons against adversary-chosen assertions. There are three problems.

First, it is false literally even in this baseline. The
[task record](../../../examples/composed-baseline/src/receiver_state.rs)
is documented as receiver-created and returned to the caller; the hardened
[receiver](../../../examples/composed-baseline/src/receiver.rs), step 26,
resolves its identifier against local state. A2A itself defines server-generated
task identifiers. A task identifier alone does not establish single-use
authorization, but its existence refutes the claimed provenance of every
arriving value. [A2A specification, Task and Message](https://a2a-protocol.org/latest/specification/).

Second, caller ownership of the token issuer is a deployment choice. RFC 8693
explicitly leaves the trust model and token semantics to profiles and
deployments. OAuth permits the authorization server and resource server to be
the same server, and permits an access token to identify stored authorization
information. None requires the receiver to accept whatever authority the
caller chooses to assert. [RFC 8693, section 1](https://www.rfc-editor.org/rfc/rfc8693.html#section-1),
[RFC 6749, sections 1.1 and 1.4](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.1).

I made this objection executable in
[receiver_owned_issuer.rs](../../../examples/composed-baseline/tests/receiver_owned_issuer.rs).
It uses the existing `ComposedReceiver`, `TokenClaims`, `CallBuilder`, and
replay store. It installs a separate receiver-owned issuer key in local state
before any request. No production receiver code, wire type, or private claim
changes.

| Attempt on the same receiver and store | Result | Cumulative tool dispatches |
| --- | --- | --- |
| Receiver-issued token | Admitted | 1 |
| Same token, new message and valid caller channel proof | `replay.token_id_seen` | 1 |
| Caller issuer signs a fresh token claiming the receiver's issuer name | `token.signature_invalid` | 1 |
| Receiver issues that next authorization itself | Admitted | 2 |

The test passes. It demonstrates that receiver issuance and resistance to
caller reminting fit the existing carrier and receiver. It does not implement
an OAuth exchange endpoint, all Chio binding checks, or crash recovery. It uses
an in-memory SQLite store and makes no durability claim. Those limits do not
rescue the assertion that these formats necessarily put every relevant value
under the caller's control.

Third, an adversary choosing the transmitted value does not invalidate an
equality check against protected state. If the attacker supplies the digest of
the exact agreement the receiver actually holds, the agreement-binding check
has succeeded. That does not prove which agreement the attacker privately
reasoned under. Chio's own
[proof companion, sections 6.1 and 6.3](../evidence-crosses/proof-model.md)
explicitly does not prove the peer's authorization or intent either.

The baseline's
[invented-field witness](../../../examples/composed-baseline/src/carriers.rs)
labels acceptance of a correctly asserted current version a surviving attack.
It has not shown that this violates the same content-binding property Chio
proves. To establish a meaningful difference, bind the request to an
authorization the receiver previously issued under a particular state, and
attempt substitution against that authorization on both implementations.
Comparing an assertion with current state is a different experiment from
proving the signer's historical decision process.

Grounding field names in published documents improves traceability. It does
not establish the limits of those documents. The
[inventory test](../../../examples/composed-baseline/tests/corpora.rs)
checks this project's selected fields and stops descending at declared
free-form slots. The
[JWT type](../../../examples/composed-baseline/src/request.rs)
rejects unknown fields, whereas JWT permits both public and private claims and
leaves required application claims to profiles. The baseline also already
invents application-specific `agreement:` and `agreement-version:` scope
values. Counting only certain extensions as invention is asymmetric.
[RFC 7519, sections 4, 4.2, and 4.3](https://www.rfc-editor.org/rfc/rfc7519.html#section-4).

The defensible result is that these base specifications do not standardize
Chio's particular semantics. That can motivate a useful profile. It is not a
result that ordinary compositions lack the carriers or authority placement
needed to implement them.

**The thesis is an engineering discipline, not the stronger theorem it needs.**

The weak reading of "the carrier is co-designed with the decision" is ordinary
interface design: make the decision's required inputs available. The stronger,
useful reading is to specify authenticated references, ownership of the state
they resolve, freshness, and consumption order together. Chio makes that
discipline concrete and testable.

Neither reading establishes that each locally checked fact needs its own wire
field. A receiver can keep an authorization record containing the argument
digest, agreement version, policy, expiry, and budget, and accept a protected
reference to that record. Local policy and current budget need not arrive at
all. An opaque token is one existing carrier for such a reference. The receiver
must still bind its caller, audience and request, check freshness, and consume
the authorization correctly. This is a counterdesign, not an implementation
claimed equivalent to Chio.

The
[Lean module](../../../formal/lean4/Chio/Chio/Treaty/AdmissionBinding.lean)
compiles. Its `accept` definition at line 576 is the statement gate conjoined
with `allFields.all (fieldAgrees st rs)`. The binding theorem projects the
equalities from that conjunction. The census establishes completeness over the
declared 55-constructor type; the executed Rust corpus checks agreement with
the chosen wire type and classifications. These are useful checks against
omission and drift. They prove neither a minimum information requirement for
authorization nor a separation from alternative protocols.

The paper acknowledges that the Rust-to-model connection is a fixture corpus,
and that the named receiver quantities are unchecked prose. That honesty is
good. The 55 leaves and 25 receiver-bound leaves should consequently carry
implementation-coverage weight, not foundational-necessity weight. Even the
fifteen-field comparison includes an admission-report digest Chio does not
compare.

**Placement is established security practice; the integration is the candidate
contribution.**

The end-to-end argument already locates functions where their required
application knowledge exists. It even discusses duplicate suppression and
delivery receipts. Chio applies that reasoning to a tool-dispatch boundary; the
paper has not yet derived a new placement principle from it.
[Saltzer, Reed, and Clark, End-to-End Arguments in System Design](https://web.mit.edu/Saltzer/www/publications/endtoend/endtoend.pdf).

There is also closer authorization prior art. KeyNote distinguishes locally
trusted policy input from signed credentials arriving over an untrusted
interface, and roots its authorization calculation in local policy. Its
application supplies action attributes and enforces the result. Proof-carrying
authentication starts from a security logic and has the requester supply a
proof that the server checks, including across administrative boundaries.
Neither is Chio's complete durable tool-execution system, but both defeat the
suggestion that receiver-rooted interpretation of remote evidence is a new
security idea. [RFC 2704, sections 2 and 5.4](https://www.rfc-editor.org/rfc/rfc2704.html#section-5.4),
[Appel and Felten, Proof-Carrying Authentication](https://www.cs.princeton.edu/~appel/papers/says.pdf).

Chio's own
[trusted-issuer construction](../../../crates/kernel/chio-kernel/src/kernel/validation.rs)
includes configured CA keys and capability-authority keys as well as the
kernel's own key. Consequently "authority is minted only inside the kernel"
needs a precise meaning: literal credential issuance is not restricted to that
key. If it means effective permission is determined by the receiver's locally
chosen roots and checks, the statement is sound as an architectural rule, but
the same interpretation must be available to the comparison systems.

**The receipt does not remove the trust premise of the decision.**

A durable, signed object connecting the request, decision, outcome, and
financial accounting is a valuable integration boundary. It can save downstream
consumers from inventing their own joins and provenance conventions.

But the paper's candidate says the record *has to* be one object. It establishes
no failure that cannot instead be prevented by cryptographically linked
authorization, execution, and accounting records. Its own operation already
uses a pre-dispatch admission record, a later receipt, and inbound and outbound
statements. A shared semantic identity is more plausible as the essential
property than physical identity of the objects.

Nor does offline signature verification make execution independently true for
someone trusting neither organization. It establishes authorship, integrity,
and the relationships actually checked. The receiving process, its key and
stores remain trusted; the paper disclaims public anti-equivocation and leaves
cross-organization settlement outside scope. The outbound countersigner checks
framing and parties but does not independently evaluate the call's policy.
The closing sentence about a verifier who trusts neither side needs this
distinction, even though the threat-model section supplies it elsewhere.

Bitcoin supplies a mechanism for selecting a shared transaction history under
an explicit majority-work assumption. Chio's single-use mechanism is local
atomic state protected by a trusted receiver. It is the right mechanism for many
tool calls, but it does not demonstrate an analogous removal of a previously
necessary trusted adjudicator. [Bitcoin, sections 2-5](https://bitcoin.org/bitcoin.pdf).

**Another flattering claim fails against the code.**

The handoff says all 536 evaluations over 268 cases assert zero dispatches on
denial and exactly one on admission. The working draft repeats that claim.
The driver does collect counts, but the assertion coverage is smaller.

In
[runtime_treaty_predicate_substitution.rs](../../../crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution.rs),
`every_pair_inside_the_binding_reference_is_rejected` at line 1106 checks the
deny verdict, absence of verified material, and a subsequent allow. It checks
neither dispatch count for any of its 120 pairs. The combined residual case at
line 1160 also omits the counts. The shared `assert_outcome` at line 1380 checks
the substituted call's count but not the follow-up call's count. Its shared
driver only copies the measurements into the result.

I tested the omission by copying that integration test temporarily and replacing
its single `dispatches: outcome.dispatches` assignment with `dispatches: 999`.
Production code and the original test were unchanged.

| Mutation experiment | Result |
| --- | --- |
| All 120 binding-reference pairs, every reported count forced to 999 | Pass |
| Combined substitution of all uncompared leaves, counts forced to 999 | Pass |
| Unsubstituted positive control, counts forced to 999 | Fails on `999 != 1` |

The [mutation record](evidence/15-breakthrough/mutation.json) pins the original
source hash. The [pair log](evidence/15-breakthrough/counter-pairs.txt),
[residual log](evidence/15-breakthrough/counter-residual.txt), and
[control log](evidence/15-breakthrough/counter-control.txt) retain the results.
The temporary test copy was removed.

This demonstrates an assertion-coverage defect, not an unauthorized dispatch in
the real kernel. The proper repair is to enforce the promised counts on every
drive and retain the counterfactual controls. The draft's macro generator counts
driver calls and checks source strings; a clean macro check does not establish
that each count was asserted.

**What the implementation checks confirmed, and what remains unqualified.**

- The recursive context scanner passes all 12 targeted tests. Its traversal
  and fail-closed bounds are implemented.
- All 22 binding-substitution tests pass. The predicate suite initially passed
  9 of 10 tests; the pair test failed because the unsubstituted follow-up was
  denied with no runtime failure code. The isolated pair rerun passed, but a
  [serial rerun](evidence/15-breakthrough/predicate-serial.txt) again passed only
  9 of 10, failing at the same assertion on a different pair. These failures
  do not establish that the continuation was consumed, and the corpus cannot
  be reported as reproducibly green. A temporary copy extending only the
  assertion's diagnostic message to print the reason and dispatch count
  [passed on rerun](evidence/15-breakthrough/predicate-diagnostics.txt), so the
  denial's cause remains undiagnosed. That temporary copy was also removed.
- All 12 federation signing tests pass, including rejection of receipt signing
  preimages on the co-signing interface. The repaired endpoint parses and
  reconstructs the bytes, so the paper's repeated "unparsed" wording is stale.
- The test covering both bilateral modes passes. The current
  `required_evidence_for_action` forces invocation evidence for both
  `bilateral_required` and `bilateral_if_cross_org`; section 6 of the draft
  still says the latter forces nothing.
- The concurrent checkpoint-read regression passes. This verifies the targeted
  local repair, not a completed rerun of the two-host experiment.
- The presentation upper bound now exists, but
  [resolved_presentation_intervals](../../../crates/kernel/chio-runtime-core/src/admission_hook/dsse.rs)
  at line 198 resolves only the treaty scope. Lease and governance registry
  intervals remain owed. The general interval type is not evidence those
  resolutions happen on live calls.
- Scratchpad driver logs support 100 admitted calls with 100 dispatches, seven
  denial classes with 140 calls and zero dispatches, and the reported clock
  offset. Their environment identifies receiver commit `1ad7544b3d`; that run
  stopped at the concurrent stage before the race and revocation stages.
  The source is the `twohost-evidence` directory under
  `/tmp/claude-1000/-home-connor-backbay-arc/2e82cf84-fc5d-4334-82be-c0e56c6ff488/scratchpad/`.
  I inspected these historical records; I did not rerun the remote experiment.
- The paper's actual checked-in `federated-pair.json` still identifies one
  host at `041aa18374`. Its sustained-load input still records the older serial
  3,543-call run at `a7f4897852`. Thus the newer work and the publishable artifact
  are different evidence states.
- `derive-macros.py --check` passes. Building the working draft into a temporary
  output directory [fails](evidence/15-breakthrough/paper-build-failure.txt)
  at section 8, line 82, on undefined
  `\PSSustainedConcurrency`. The existing paper sources and PDF were preserved.

The handoff's remaining lease/governance resolution, denial co-signature, and
budget-unwind issues should stay explicit work items. The judgment above does
not turn those requirements into weaker product goals.

**The single strongest objection to my conclusion.**

A breakthrough can be a composition of familiar mechanisms that makes a
previously impractical activity routine. Requiring a new cryptographic primitive
or an impossibility theorem would be the wrong test. Chio could make secure,
accountable interorganizational agent execution cheap enough to become a normal
programming model. A standards-compatible counterdesign does not disprove that
possibility; it may merely show how much engineering Chio saves its users.

That is the strongest case for Chio, and this evaluation has not measured it.
The baseline implements selected small formats and a small policy evaluator.
It does not measure what independent organizations must implement, maintain,
and trust to obtain the same complete behavior.

**What would change my mind.**

An independently implemented receiver, built from the contract without sharing
Chio's admission code, should join a real multi-organization workflow and safely
consume the same evidence under its own roots, policy, revocation, budgets, and
crash recovery. A third party should reconstruct exactly the claimed decisions
and accounting from the exported records under an explicit trust model.

Compare that workflow with a serious receiver-issued-token or protected-handle
implementation, permitting the same local policy, storage and ordinary
extension mechanisms. Match the adversary, the definition of an authorized
operation, and the failure schedule. Measure total partner integration work
and operational burden as well as correctness and latency.

If Chio turns what requires repeated bespoke security integration into one
reusable contract across independently built receivers, that would support a
practical breakthrough. A new theorem identifying a necessary cross-system
invariant, with an implementation and counterexamples that actually depend on
it, could support a conceptual one. More counted leaves or a weaker baseline
would not change this judgment.

**Reproduction.**

```sh
cargo test --locked --manifest-path examples/composed-baseline/Cargo.toml --test corpora
cargo test --locked --manifest-path examples/composed-baseline/Cargo.toml --test receiver_owned_issuer
cargo test --locked -p chio-runtime-core --test runtime_agreement_context_scan --test runtime_treaty_binding_substitution --test runtime_treaty_predicate_substitution
cargo test --locked -p chio-runtime-core --test runtime_treaty_predicate_substitution -- --test-threads=1
cargo test --locked -p chio-federation --test bilateral_signing
cargo test --locked -p chio-runtime-core --test runtime_treaty every_two_signature_co_sign_mode_requires_the_invocation_record -- --exact
cargo test --locked -p chio-store-sqlite --lib concurrent_point_loads_do_not_see_projection_drift_while_checkpoints_commit
(cd formal/lean4/Chio && lake env lean Chio/Treaty/AdmissionBinding.lean)
python3 docs/papers/evidence-crosses/tools/derive-macros.py --check
```

The existing baseline corpus passes all eight tests. The additional issuer
counterexample passes, as do its targeted Clippy run with warnings denied and
its formatting check. No benchmark timing, full-workspace qualification, or
remote deployment claim is made from these local checks.
