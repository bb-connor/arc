# Conformance, executable trajectories and comparative evaluation

## Evidence levels

Architecture validation checks coverage, consistency, model assumptions and source references. Pure evaluator tests check algebra and signed bindings. Native integration tests check actual stores, capture and dispatch. Process/crash tests check persisted ownership across OS death. Hosted confinement tests establish a particular enforced deployment. Matched live workflows measure useful behavior and operational cost.

Keep these results separate in every report. The earlier 104-test research pass supports the existing foundation and a preparation prototype. It does not validate the new grant v2, recovery participant, artifact protocol or confined-return implementation specified here.

## Trajectory format

Extend existing replay/conformance tools with a closed `RecoveryTrajectoryV1` fixture. Fields include fixture/schema version; source/contract/policy/profile digests; initial identities/labels/capabilities; deterministic clock and provider facts; ordered or scheduled commands; injected cutpoints; expected decision categories/offers; expected authority-consumption and native-effect assertions; artifact/parent-state assertions; and final verified evidence references.

Fixtures use symbolic test identities resolved by the harness, not real private keys or provider credentials. The model-free harness uses real Rust policy/flow/grant verification, real serving/process stores and a counting or authoritative local effect endpoint. A pure mock store result cannot satisfy a native durability case.

Assertions include allowed useful work, exact calls/effects, no duplicate effect, exact retained operation identity, remaining budget, grant state, monotone knowledge, permitted recipient, unchanged immutable request, parent-return evidence and original-result recovery. A test that only checks a `Deny` string is insufficient for effect safety.

## Required campaigns

| Campaign | Positive counterpart | Adversarial/fault cases |
|---|---|---|
| Exact disclosure | One reviewed send and restart recovery | Payload/recipient/purpose/capability/tenant/continuation substitution; v1 downgrade; wrong authority |
| Composite approval | Multiple affected authorities authorize the same exact target | Partial owner set, wrong power, source/action/challenge substitution, duplicate signer aliases, broader target under unchanged arguments, digest cycles |
| Request custody and native attachments | Original strict nonce recovers through process reopen | Lost issuance acknowledgement, missing signed envelope, changed process hash after nonce attachment, preflight before admission intent, renewal of expired unbound nonce |
| Historical settlement authority | Expired or cancelled initiator's owned effect settles internally | Ordinary invoke required for recovery, substituted maintenance capability dispatch, unscoped provider lookup, historical result released to revoked audience |
| Concurrent recovery | Same selection converges to one continuation | Two coordinators, stale epochs, duplicate approvals, conflicting command IDs, lost commit acknowledgements |
| Process/admission bridge | One quota charge and exact native operation recovery | Request-only binding, changed host route/profile, admission before link acknowledgement, late submit after closure |
| Partial effects and release | Settled failure reports effects; later authorized result release | Non-success treated as no effect, duplicate provider retry, withheld output triggering resend |
| Replay authorization | Lost successful response recovers its command | Stale expected revision checked too early, revoked audience receives cached bytes, changed challenge coverage addresses new row |
| Issuance and plan causality | One exact grant; useful prerequisite followed by exact review | Sign/attach/publish crashes, silently renewed expiry, future-output placeholders, result substitution, cancellation racing capture |
| Effect truth | Completed result recovers without another effect | Denied-after-delivery, completed denial with unknown resource, capture ambiguity, caller-report loss |
| Basis freshness | Stable exact review remains usable | Policy/contract/source/ACL/revocation/time changes; budget exhaustion; unrelated tenant changes |
| Semantic coverage | Two useful tool families resolve exact recipients | Uncovered nested tool, schema drift, redirects, provider account substitution, partial membership results |
| Transform/withhold | Authorized derived output or completed no-value action | Raw fallback on failure, wrong executable, input/output substitution, reused one-shot authority |
| Artifact memory | Restart/restore preserves useful readable content | Lost labels, corrupt blob, alias/concurrent write, stale checkpoint, cross-tenant digest probing, GC race |
| Observation ordering | Artifact/return joins native knowledge before release | Missing join, uncertain commit, stale egress preparation, provider-context rebinding |
| Confined return | Parent completes a decision from an authorized bounded result | Tainted seed, forged epoch, unverified launch, reused provider context, hidden logs/errors/streams |
| Policy maintenance | Reviewed fix enables benign task | Complaint-induced privilege expansion, permissive outage fallback, policy rollback replay |

Every security negative has a benign case showing that the relevant feature can succeed. Each mutation test must fail for its intended invariant, not an earlier exhausted quota, malformed fixture, expired unrelated token or missing harness setup. Retain original failing evidence when correcting fixtures.

## Rust verification strategy

Use unit/property tests for label/influence joins, normalized selectors, basis hashing, plan ordering and version decoding. Property checks include idempotence/associativity/commutativity where the algebra requires them; bounded overflow must preserve restrictive unknown behavior.

Use compile-fail tests for invalid construction/retargeting of live handles and unsupported evidence-to-authority conversions. Use the repository's existing concurrency/model tools for actual store/owner synchronization; a Rust type alone does not prove crash consistency. Fuzz signed parsing, schema conversions, selectors, graph bounds, artifact manifests and transition decoders. Run parser/canonicalization vectors across generated languages.

The P0 matrix includes Rust 1.93 checks for the existing substrate crates and their proof-tool compatibility, plus supported no-default-feature/WASM builds. Test feature-isolated pure crates and unified workspace features separately. Assert dispatch-owner auto traits and consuming APIs without adding unsafe implementations. Vary insertion/scheduling order and verify identical planner decisions/canonical bytes. Malformed-input tests include depth, aggregate allocation and repeated evidence expansion, not only envelope size.

Inject abrupt OS exit and uncertain store acknowledgement before and after each protocol cutpoint. Restart with a fresh process and exact persisted stores; count actual endpoint effects and verify retained evidence independently. Include torn/incomplete metadata, stale process snapshots, key/policy reload, dropped caller reports and restore/GC races. A clean shutdown is not a substitute for a crash test.

## Architecture model

The included [bounded Rust model](model/recovery.rs) explores two coordinators and two possible continuations for one effectful workflow step. It abstracts cryptography, provider correctness, storage bytes and time. Atomic transitions stand for the specified authoritative transactions; the model does not prove those transactions are implemented.

It checks exclusive unresolved ownership, no new continuation after successful completion, no fresh dispatch for unknown outcomes, stale-epoch refusal and at most one effect for the modeled step. Mutation modes intentionally remove selected guards and must yield counterexamples. Its finite state exploration is evidence about the protocol abstraction, not a theorem about all production executions. Liveness and fairness require separate implementation/load evidence.

When implementation begins, map each modeled transition to the owning kernel/store function and cutpoint test. Extend the model for process-authority reservation bridging, prerequisite DAGs and artifact publication before claiming those protocols model-checked. Never silently broaden the model's stated coverage.

Revision 2 adds independent bounded seam models for admission intent versus missing projections and cancellation, observation/egress ordering, replay authorization, and partial-effect settlement. Their assumptions and results are separate from the original ownership model. They do not model the complete two-store bridge, provider idempotency service, cryptography or artifact byte custody. Each deliberate fault must fail for the expected invariant. Retained results bind exact model-source hashes and compiler identity; edited models cannot inherit stale passing output.

Revision 3 adds a bounded exact-envelope/nonce protocol, including one crash, lost issuance acknowledgement, cancellation/expiry and original-operation settlement. It requires a reachable useful restart and locally enabled internal settlement even after initiating authority expires; this is not a proof of eventual scheduling. A separate finite coverage corpus models four distinct authority obligations and four exact context bindings, including duplicate-principal aliases. It assumes authentic scoped attestations and does not exercise production signatures, the full label algebra or actual SQL. Existing process nonce tests are rerun separately as foundation evidence, not as tests of the proposed grant-v2 integration.

## Comparative benchmark

Run two unrelated workflows on two host frameworks with the same model/version, tasks, tool semantics, provider/resource behavior, authority policy and bounded budgets. The first workflow is support-to-public-issue recovery. The second should exercise confined research plus a bounded returned decision or protected artifact reuse. Select its concrete tools before collecting results; do not tune the task set after seeing which system wins.

Include a competent baseline with stable operation IDs, idempotency, outcome lookup and normal provider ACLs. Compare OpenAPPA only over semantics each integration actually covers; report unsupported cases. Different label algebras require a documented common task policy, not an assumed label-to-label equivalence.

Measure legitimate completion, unauthorized effects, duplicate effects, unnecessary approvals, recovery success, unresolved outcome count/age, source-label retention, actual host supervisory code removed, installation steps, execution latency, model tokens, external consults and runtime overhead. Report denominators, repetitions, distributions and confidence intervals for stochastic work. Zero observed violations is corpus-bounded evidence. Never collapse safety and utility into a single opaque score.

Performance acceptance is initially non-regression against the recorded native baseline under a predeclared threshold, plus bounded resources under overload. Establish the numeric latency/throughput/error budgets during P0 measurement, before optimizing or running the comparative trial; this specification does not invent measurements. Pure planner, store commit, external consult, human wait and model cost must be reported separately.

## Obligations

| ID | Normative obligation | Proposed acceptance test | Phase |
|---|---|---|---|
| TEST-01 | Trajectories MUST assert effects, authority and retained knowledge alongside decisions. | `conformance::trajectory_effect_assertions` | P0 |
| TEST-02 | Every security negative MUST have a successful relevant benign counterpart. | `conformance::paired_case_inventory` | P1 |
| TEST-03 | Crash campaigns MUST use fresh processes and independent effect/evidence checks. | `conformance::native_os_death_cutpoints` | P1 |
| TEST-04 | Mutation tests MUST reject the intended broken invariant rather than incidental fixture failure. | `conformance::mutation_reason_coverage` | P1 |
| TEST-05 | Concurrency/parser/model tests MUST map to actual owning components before qualification. | `conformance::source_bound_assurance_map` | P6 |
| TEST-06 | Comparative trials MUST match tasks, actors, authority and competent recovery baselines. | `evaluation::matched_trial_manifest` | P6 |
| TEST-07 | Published metrics MUST preserve denominators, uncertainty, unsupported cases and source/profile identity. | `evaluation::report_provenance_and_denominators` | P6 |
| TEST-08 | Feature acceptance MUST include bounded-resource overload and declared performance budgets. | `conformance::resource_and_latency_budget` | P6 |
