# Design: integrity-gated admission

- Status: PROPOSED (revision 1, baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5)
- Date: 2026-10-04
- Scope: make "untrusted data cannot cause a consequential tool call" a property the kernel enforces for any agent framework. It is built from the shipped and implemented knowledge (P4), semantic (P3) and confinement (P5) surfaces:
  - grants declare a required integrity;
  - the kernel records the influence of every output it delivers into a mediated context;
  - an early deny-only guard checks the calling context's influence, and the authoritative check runs inside the intent commit;
  - refusals become a classified, anti-oracle fault whose remedies run through recovery.

  It adds no interpreter, no taint tracking inside model reasoning, and no reduction of influence history.
- Owners:
  - `chio-core-types`: the `RequiredIntegrity` constraint and the integrity requirement vocabulary.
  - `chio-security-types`: the influence state, origin classes and typed return contracts.
  - `chio-kernel`: `IntegrityGuard`, crossing check 4, and fault classification.
  - `chio-store-sqlite`: output influence joins and the influence summary row.
  - `chio-control-plane`: operator origin bindings and confined typed returns.
  - `chio-process` and the SDKs: initial context influence from the worker profile.
- Related:
  - W: `docs/architecture/recoverable-agent-runtime/01-security-model.md` (the proposed `InfluenceState`, SEC-05), `05-semantic-contracts.md` (P3), `06-artifacts-memory.md` (P4), `07-confined-returns.md` (P5).
  - M: `docs/security/active-defense-rollout.md` (isolation-epoch successors), `crates/kernel/chio-process/MAILBOXES.md`.
  - `spec/PROTOCOL.md` sections 5, 6 and 8.
- Citation convention:
  - M: = `origin/integration/process-security-m4` at `19df31ad9`.
  - V: = `origin/work/verifiable-work-session-20261003` at `14477aaac`.
  - R: = `origin/research/openappa-recovery-20261001` at `de84fc306`.
  - W: = the uncommitted recovery working tree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`. Its line references reflect 2026-10-04 and may drift.
  - P: = `feat/process-command-experience-20260924`.
  - B: = `origin/wip/bench-results-2026-09-13`.
  - W1-W4 and doc-only R: names are contract anchors.
- Origin: `docs/research/2026-10-04-chio-kernel-north-star.md`, bet 3.
- Siblings:
  - the umbrella `2026-10-04-ftl-lessons-program-design.md`;
  - the program specs: `closed-kernel-abi`, `authority-faults`, `typed-reservations`, `authority-space-teardown`, `unified-event-queue`, `opaque-adapter-context`, `microkernel-isolation-backend`, `durable-stop-epoch`;
  - the north-star specs `2026-10-04-pure-admission-machine-design.md` (A) and `2026-10-04-crossing-primitive-design.md` (B).

## 1. Decision summary

The research consensus is that prompt injection is contained outside the model:
- In-model defenses fall to adaptive attacks, all eight evaluated, consistently above 50 percent success ([arXiv 2503.00061](https://arxiv.org/abs/2503.00061)).
- Systems that hold up enforce a deterministic dataflow rule: once untrusted content has entered a context, it cannot trigger a consequential action ([Design Patterns, arXiv 2506.08837](https://arxiv.org/abs/2506.08837)).
- CaMeL enforces this in a custom Python interpreter ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)), and FIDES in one planner ([arXiv 2505.23643](https://arxiv.org/abs/2505.23643)).

Chio already has the primitives at the operating-system layer:
- **P4** keeps a monotone knowledge join per principal, lineage and session in the serving writer.
- **P5** cages a zero-authority reader that returns a typed value.
- **P3** binds endorsements to one exact action.

The recovery security model already specifies the integrity contract (W: `01-security-model.md:23`):
- an `InfluenceState` retaining the union of observed origin classes plus `Unknown`;
- tool contracts declaring acceptable influence sets;
- a scoped endorsement that authorizes an exact action "despite those influences; it does not rewrite global influence history".

Three things are missing:
1. **Admission does not consult influence.** Integrity gating today exists only inside P3 semantic contracts.
2. **Tool output delivered to a worker records no influence.** The `CapturedOutput` release kind is defined but never produced (W: `chio-security-types/src/knowledge/release.rs:58-61`).
3. **Every published artifact is marked externally influenced unconditionally** (W: `.../knowledge/traversal.rs:67`). Nothing can be trusted, so a gate built on today's state would deny everything.

This design closes all three:

1. **The lattice.** An integrity lattice taken from W:'s implemented influence record and the proposed origin classes (section 4). It adds a bounded-capacity class for typed confined returns.
2. **Output influence joins.** Every output the kernel delivers into a mediated context joins its influence, and origin classes are assigned by operator bindings (section 5).
3. **`Constraint::RequiredIntegrity`.** It follows the `MinimumRuntimeAssurance` precedent and is preserved monotonically under delegation (section 6).
4. **Two checks.** A deny-only `IntegrityGuard` runs early (section 7). The authoritative check is crossing check 4 inside spec B's intent commit, in the same writer as the joins (section 8).
5. **The fault.** `InsufficientIntegrity` joins spec 2's taxonomy (section 9). Its remedies are:
   - an exact endorsement, through the existing but unused `AuthorityObligationV1::IntegrityEndorsement`;
   - a quarantined continuation in an isolated successor fed by typed P5 returns.

## 2. Verified current state

| Fact | Evidence |
|---|---|
| Confidentiality labels are owner-to-reader policies plus compartments, with `Top`, and support `join_restrictions` and `flows_to` | W: `crates/security/chio-security-types/src/flow.rs:44-51`, `:362`, `:401` |
| Influence is recorded as `ArtifactInfluenceV1 { commitment, externally_influenced, unknown }` on every artifact version, release and checkpoint | W: `chio-security-types/src/knowledge/artifact.rs:15-19`, `:65`; `knowledge/release.rs:72`; `knowledge/checkpoint.rs:16` |
| A context's influence is the OR over knowledge-join records in the same tenant and isolation epoch whose principal, lineage *or* session matches. It is computed inside a writer transaction | W: `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/knowledge.rs:52-87` |
| Published artifacts are always marked `externally_influenced: true` | W: `.../admission_operation_store/knowledge/traversal.rs:43-73`, `:67` |
| `ArtifactReleaseKindV1::CapturedOutput` has no producer, so ordinary tool output records no join | W: `knowledge/release.rs:58-61`; no constructor in W: crates |
| Capture and knowledge join serialize through one writer. "Knowledge committed first refuses stale native preparation"; "a later dispatch check may refuse changed knowledge" | W: `docs/.../implementation/p4/OPERATIONS.md:107-113` |
| The proposed `InfluenceState`: origin classes plus `Unknown`; tool contracts declare acceptable sets; a scoped endorsement authorizes exact actions without rewriting history | W: `docs/.../01-security-model.md:23` |
| SEC-05: "Disclosure/endorsement MUST NOT reduce retained confidentiality or influence history" | W: `01-security-model.md:55` |
| P3 operations declare `external_influence`, and verification ORs it into the action's influence | W: `chio-security-types/src/semantic/package.rs:84`; `chio-semantic-contracts/src/verification.rs:156`, `:199` |
| P3 `ScopedEndorsementV1` binds an exact action digest, the influence digest, destination and purpose, and supplies the contract's required assertions. "Integrity endorsements cannot change this confidentiality comparison" | W: `semantic/evidence.rs:84-101`; `verification.rs:205`, `:237-282` |
| P5 `ReturnContractV1` admits only one 8-byte value on the `Value` channel, with `require_integrity`. The host recomputes a canonical boolean projection | W: `chio-security-types/src/confinement.rs:51-82`; `chio-core-types/src/recovery/confinement.rs:58-73` |
| P5 return admission requires an independently rooted endorsement when `require_integrity` is set, but copies the observation's influence into the parent release | W: `.../knowledge/confinement/returns.rs:356-372`, `:383` |
| `AuthorityObligationV1::IntegrityEndorsement { principal }` exists with no consumer. `AuthorizationRequirementsV1` binds an `influence_basis` | W: `chio-security-types/src/recovery/authorization.rs:39-44`, `:47-62` |
| Planner vocabulary: facts `Capability`, `Policy`, `DestinationAcl`, `AuthorityCoverage`, `Transformation`, `Prerequisite`; remedy kinds `ExistingDestination`, `ExactApproval`, `Transformation`, `Prerequisite` | W: `chio-security-types/src/recovery/explanation/snapshot.rs:5-12`; `registry.rs:6-11` |
| `ToolGrant` has constraints and caps, and `Constraint::MinimumRuntimeAssurance` is a tier constraint. Constraint preservation under delegation defaults to equality | M: `crates/core/chio-core-types/src/capability/scope.rs:95-118`, `:331`, `:359`, `:602` |
| KG4: issuance is exhaustive over `Constraint` | M: `crates/kernel/chio-kernel/src/authority.rs:102-137` |
| `Guard` with opt-in dispatch revalidation | M: `crates/kernel/chio-kernel/src/kernel/mod.rs:870-899` |
| The confidentiality flow guard `FlowPreInvocationGuard` takes a `MissingContextPolicy { Allow, Deny }`. No integrity guard exists | M: `crates/security/chio-security-kernel/src/pre_invocation.rs:62`; `lib.rs:49-59`; chio-flow modules are classification, declassification, engine and lattice |
| The tool manifest carries a publisher-authenticated `flow` (confidentiality only) and annotations `read_only` and `destructive` | M: `crates/core/chio-core-types/src/manifest.rs:143`, `:186`, `:188`; W: `flow.rs:269-277` |
| The security context comes only from a trusted runtime boundary. Process calls set session to the runtime id and lineage to the process lineage | M: `kernel/mod.rs:225-241`; `crates/kernel/chio-process/src/security.rs:28-46` |
| "Messages and tool outputs are untrusted data". `attest_senders` records the kernel-selected sender | M: `crates/kernel/chio-process/MAILBOXES.md:33`, `:61` |
| "Only a verified isolation-epoch transition starts an isolated successor"; taint survives session closure | M: `docs/security/active-defense-rollout.md:19`; W: `ports_parts/part_01.rs:813` (`IsolationEpochTransition`) |

## 3. Goals and non-goals

Goals:
- A grant can require that its call come from a context with no unendorsed external influence, and the kernel enforces it for every framework running as a mediated process.
- Influence tracks what actually entered a context: tool outputs, mailbox messages, artifact reads, model-context restores and confined returns.
- Refusals are recoverable through endorsement or quarantine without weakening the guarantee.
- The guarantee is measured under adaptive attack, and published.

Non-goals:
- Taint inside model reasoning or per token. NeuroTaint argues string-level taint fails ([arXiv 2604.23374](https://arxiv.org/abs/2604.23374)). This design is sound at context granularity and does not claim more.
- Clearing a context's influence. SEC-05 forbids it.
- Certifying integrity for contexts the kernel does not mediate completely (section 12).
- Replacing confidentiality flow control. This design is orthogonal to `InformationLabel` and never changes a confidentiality comparison.

## 4. Integrity lattice

The lattice is W:'s implemented influence record, read as a three-point order, plus the proposed origin classes as one refinement step.

```rust
// chio-security-types::knowledge (extends the proposed InfluenceState, W: 01-security-model.md:23)
pub enum InfluenceOriginV1 {
    External,                                // tool output, provider fetch, mailbox from an unattested sender
    ExternalBounded { max_bits: u16 },       // typed P5 return; capacity bound by its contract (section 10)
    ModelProvider { provider: ProviderId },  // operator-bound provider responses
}

pub struct InfluenceStateV1 {
    pub origins: BoundedSet<InfluenceOriginV1, 32>,  // union of observed classes; empty means trusted
    pub bounded_bits_total: u32,                     // sum over ExternalBounded joins, saturating
    pub unknown: bool,                               // provenance unknown anywhere in the context
    pub commitment: CanonicalPayloadDigest,          // chains every joined ArtifactInfluenceV1
}
```

Projection from the implemented record:
- `unknown` maps to `unknown`;
- `externally_influenced` maps to `External` in `origins`;
- otherwise the state is trusted, with empty origins.

The proposed refinement adds `ExternalBounded` and `ModelProvider`. It is additive, as W: requires ("requires new native participant evidence before deployment").

Order and join:

```text
s1 <= s2  iff  s1.origins subset-of s2.origins
               and s1.bounded_bits_total <= s2.bounded_bits_total
               and (s1.unknown -> s2.unknown)
join(s1, s2) = (origins: union, bounded_bits_total: saturating sum, unknown: or,
                commitment: H(s1.commitment, s2.commitment))
bottom = trusted (empty origins, 0 bits, known);  top = unknown
```

The requirement a grant declares:

```rust
pub enum IntegrityRequirementV1 {
    Trusted,                                      // no external origin, known provenance
    BoundedExternal { max_bits: u16 },            // only ExternalBounded origins, total <= max_bits
    ProviderOnly { providers: BoundedSet<ProviderId, 8> }, // Trusted plus listed providers
}
```

Normative rules:

1. **I1. Satisfaction.** `satisfies(state, req)` is false whenever `state.unknown`.
   - `Trusted` requires empty origins.
   - `BoundedExternal { n }` requires every origin to be `ExternalBounded` and `bounded_bits_total <= n`.
   - `ProviderOnly(ps)` requires every origin to be `ModelProvider { p }` with `p` in `ps`.
2. **I2. Monotone.** Joins only move up the order, and nothing in this design moves a context down, so `satisfies` can only go from true to false within one context.
3. **I3. Requirement order.** For attenuation: `Trusted` is stronger than `BoundedExternal { n }`, which is stronger than `BoundedExternal { m }` when `n < m`. `ProviderOnly(ps)` is stronger than `ProviderOnly(qs)` when `ps` is a subset of `qs`. `Trusted` is stronger than every `ProviderOnly`.

## 5. Output influence joins

Today the influence of a context reflects only P4 artifact traffic. The main injection vector is a tool output entering a worker's model context, and it is untracked.

4. **I4. Join on delivery.** Every output the kernel delivers into a mediated context joins its influence into that context's knowledge flow rows. The join happens in the serving writer, in the same transaction as the outcome commit or release (spec B). Delivered outputs are:
   - process `invoke` results;
   - kernel-session tool results;
   - mailbox `receive` payloads;
   - artifact reads;
   - model-context restores;
   - confined returns.

   The previously unproduced `ArtifactReleaseKindV1::CapturedOutput` becomes the release record for invoke results under enforced knowledge.
5. **I5. Origin assignment.** Origins come from an operator-signed `IntegrityDeploymentBindingV1`, never from the output and never solely from the tool publisher:
   - **Default.** Every route's output origin is `External`. An unbound route is `External`, never trusted (fail closed).
   - **Operator trust.** An operator may bind a route as `Trusted`, for an internal deterministic tool over operator-controlled data, or as `ModelProvider { provider }`. The binding names the server, the tool and the tool server's manifest digest. A manifest change voids it.
   - **Publisher declarations.** A publisher's `ToolFlowDeclaration` may only add influence, through a new optional `output_influence: External` field. It can never assert trust, matching P3's "publisher signatures confer no tenant authority".
   - **Replaces the unconditional marking.** The unconditional `externally_influenced: true` at W: `traversal.rs:67` becomes the join of the published inputs' actual influence states.
6. **I6. Mailboxes.**
   - A `receive` payload inherits the sender's influence state, recorded at `send` in the same transaction, when the channel has `attest_senders` (M: `MAILBOXES.md:33`).
   - Without sender attestation, its origin is `External`.
7. **I7. Initial influence of a context.** It comes from the host-sourced `worker_profile` attribution (`2026-10-04-microkernel-isolation-backend-design.md` section 6.3):
   - **`direct`** starts at `unknown = true`. The worker can ingest anything outside mediation.
   - **`container`** starts at trusted only when the run plan pins every input, the image digest, task input and seeds. Otherwise it starts at unknown.
   - **`split_domain`** starts the controller domain at trusted. Execution-domain results arrive as ordinary tool outputs, `External` unless bound otherwise.
   - **`confined_reader`** is not applicable: it has no tools.

   Kernel sessions (MCP edges) start at unknown (section 12).
8. **I8. Confined returns are bounded, not cleared.** A P5 return joins `ExternalBounded { max_bits }` into the parent, where `max_bits` is the capacity of its return contract (section 10). It does not copy the observation's full influence as `External`, which is today's `returns.rs:383` behavior. The original influence is retained in `commitment`, so history is not reduced (SEC-05).
   - This is the one place where the class of a join differs from its source. It is justified because the parent receives only a host-recomputed value of at most `max_bits` bits, and every other channel is withheld (W: `confinement.rs:15-25`).
   - When the contract sets `require_integrity`, the return additionally needs its independently rooted endorsement, as today.

## 6. Declaring the requirement

`Constraint::RequiredIntegrity(IntegrityRequirementV1)` is a new constraint variant. A constraint, rather than a `ToolGrant` field, gives:
- conjunctive composition with other constraints;
- KG4's exhaustive enforcement decision;
- the portable core's fail-closed handling;
- the existing tier-constraint precedent (`MinimumRuntimeAssurance`, M: `scope.rs:359`).

9. **I9. Preserved monotonically.** `is_preserved_by` gains an explicit arm, so the default equality rule does not apply (M: `scope.rs:602`):

   ```text
   (RequiredIntegrity(p), RequiredIntegrity(c)) => stronger_or_equal(c, p)
   ```

   A delegation may raise the requirement, keep it, or add it, and never weaken or drop it (`is_subset_of` requires every parent constraint to be preserved).
10. **I10. KG4.** `ensure_capability_issuance_supported` (M: `authority.rs:102`) lists `RequiredIntegrity` as supported only when the receiving kernel has durable knowledge enforcement and the integrity crossing check installed. Otherwise issuance rejects it with the existing "grant-specific enforcement is unavailable" error.
11. **I11. Portable core.** `chio-kernel-core` has no knowledge store. It treats the constraint as unevaluable and fails closed with a `ConstraintError`, so browser, mobile and C FFI kernels deny integrity-gated grants.
12. **I12. Deployment floor.** An operator may set `integrity_floor` per effect class, from the tool annotations `destructive` and not-`read_only` (M: `manifest.rs:186-188`) and the monetary effect class.
    - The floor applies as if the constraint were present on every matching grant.
    - It may only raise requirements, and it is recorded in receipts (section 13).
    - The default floor is none, so v1 is opt-in per grant (open decision 1).

## 7. `IntegrityGuard` (early)

13. **I13. The guard.** `IntegrityGuard` is a deny-only `Guard`:
    - **Inputs.** For each matched grant carrying `RequiredIntegrity` (or a floor), it reads the calling context's influence through a read-only `IntegrityStatePort`, keyed by the trusted `SecurityInvocationContextV1` (M: `kernel/mod.rs:234`).
    - **Missing context.** It always denies. Unlike `FlowPreInvocationGuard`, there is no `MissingContextPolicy::Allow`, because the requirement is signed into the grant.
    - **Unavailable port.** It denies.
    - **Revalidation.** It sets `requires_dispatch_revalidation() = true` and repeats the read before dispatch (M: `kernel/mod.rs:882`).
14. **I14. Advisory only.** The early read and the revalidation are best-effort latency savers. Neither decides an effect (section 8).

## 8. Authoritative check: crossing check 4

A join and a capture can race. A tool output can be delivered into the same context, and commit its join, between the guard's read and the dispatch. P4 already resolves the analogous confidentiality race by serializing capture and join in one writer (W: `p4/OPERATIONS.md:107-113`). Integrity uses the same point.

15. **I15. Inside the intent commit.** Spec B's crossing primitive evaluates `CrossingCheck::KnowledgeIntegrity { key, requirement }` inside the intent commit's writer transaction, before `DispatchCommitted`. For a read-only call there is no intent commit. The same check runs inside spec B's check-only dispatch crossing, which reads the committed influence head in the writer without writing, so read-only tools gated by integrity are covered too. `satisfies` is computed from the influence state as committed in that same transaction.
    - **Join first:** a join that commits first makes the intent commit fail with `InsufficientIntegrity`.
    - **Intent first:** the effect proceeds, and the later join affects only later calls.
16. **I16. Summary row.** W:'s `observed_influence` scans up to 4,096 join records per call (W: `security_participant_state/knowledge.rs:64-75`). This design adds `knowledge_influence_heads(tenant, isolation_epoch, scope_kind, scope_id) -> InfluenceStateV1`, updated in the same transaction as every join (I4).
    - Crossing check 4 reads the principal, lineage and session rows and joins them, which is O(1).
    - A startup check recomputes each row from the journal and refuses readiness on mismatch.
17. **I17. Key semantics unchanged.** The check uses W:'s key semantics: the union of rows matching principal, lineage or session within tenant and isolation epoch. Narrowing is a later decision (section 11).

```text
committed(join(ctx, s)) before intent_commit(op) and key(op) = ctx and not satisfies(s', req(op))
  -> not DispatchCommitted(op)                     (s' = state after the join)
DispatchCommitted(op) -> satisfies(state_at(intent_commit(op)), req(op))
forall ctx: state(ctx) only increases              (I2; SEC-05)
```

## 9. Refusal, fault and remedies

18. **I18. A fifth class.** `InsufficientIntegrity` joins spec 2's closed `AuthorityFaultClass` (`2026-10-04-authority-faults-design.md` section 5). It is classified from the guard or crossing-check refusal. A request that presents an integrity endorsement (I21) never yields this fault, which avoids fault-on-fault loops.
19. **I19. Anti-oracle.** The fault block carries only:
    - the class;
    - the caller's own requirement, which the caller holds;
    - the surface (`guard` or `crossing`);
    - the remedy classes available.

    It never carries origin classes, bit totals, the commitment, or which delivery caused the taint. With session-wide keys (I17), the cause may be another process's delivery in the same runtime, so revealing it would leak cross-process activity. `ExplainIntent`-equivalent projections follow P2's stricter rules.
20. **I20. Planner fact.** Where a recovery deployment covers the request, the kernel exposes a new `ExplanationFactKind::Integrity` with value `false`. W:'s fact enum is closed, so this is a schema change. Only two remedy paths may address it:
    - `ExactApproval` with obligation `IntegrityEndorsement` (I21);
    - `Prerequisite` with the `QuarantinedContinuation` template (I22).

    No other remedy kind may address it, and the planner returns `NoRegisteredRemedy` otherwise.
21. **I21. Endorsement.** An approver on the deployment's integrity roster signs an exact approval whose `AuthorizationRequirementsV1.obligations` contains `IntegrityEndorsement { principal }`. Its `influence_basis` equals the context's committed influence digest (W: `authorization.rs:44`, `:55`). The approval authorizes exactly one continuation despite the influence.
    - **History.** The context's state is unchanged (SEC-05). The next consequential call needs its own endorsement.
    - **Semantic connectors.** For P3 connectors, the existing `ScopedEndorsementV1` over `ExactAction` (W: `semantic/evidence.rs:84-87`) is the same rule, already implemented, and satisfies the crossing check for that action.
22. **I22. Quarantined continuation.** The remedy that recovers utility without a human:
    1. A verified isolation-epoch transition starts an isolated successor whose influence starts trusted (M: `active-defense-rollout.md:19`).
    2. The tainted parent hands its untrusted artifacts only to P5 confined readers.
    3. The readers' typed returns join the successor as `ExternalBounded` (I8).
    4. The successor performs the consequential call under a `BoundedExternal { n }` requirement.

    This is the Design Patterns paper's dual-LLM and action-selector patterns, enforced by the kernel rather than by framework discipline.

## 10. Typed return contracts (generalizing P5)

`ReturnContractV1` admits only an 8-byte boolean today (W: `confinement.rs:67-79`). This design adds a closed return-type library, recomputed by the host exactly as the boolean projection is (W: `chio-core-types/src/recovery/confinement.rs:58-73`):

```rust
pub enum ConfinedReturnTypeV1 {
    Boolean,                                                   // 1 bit
    Enum { variants: BoundedList<ProtectedText<64>, 256> },    // ceil(log2(n)) bits
    Integer { min: i64, max: i64 },                            // ceil(log2(max - min + 1)) bits
    Identifier { max_len: u8, charset: IdentifierCharsetV1 },  // max_len * log2(|charset|) bits, max_len <= 64
}
```

23. **I23. Capacity.** Each type has a fixed capacity in bits, which becomes `ExternalBounded { max_bits }`.
    - `Identifier` uses a restricted charset (ASCII letters, digits, `.`, `_`, `-`), with no spaces and no punctuation that can form instructions. Free text is not a return type.
    - The host projection rejects any value outside the type. There is no fallback.
24. **I24. Return discipline unchanged.** One value, on the `Value` channel only, with every other channel withheld. `max_bytes` is derived from the type, up to 64.

## 11. Granularity and utility

- **Soundness.** It holds at context granularity. A context that never received an unbounded external join cannot be steered by external content through Chio-mediated channels. Influence at finer grain is heuristic and out of scope.
- **Over-taint.** W:'s keys join principal, lineage and session, and process calls use the runtime id as session (M: `chio-process/src/security.rs:28-46`). One process's untrusted delivery therefore taints every process in that runtime.
  - This is conservative, and correct while processes can exchange data through mailboxes, blobs and spawn inputs.
  - Narrowing to lineage requires every inter-process channel to carry influence (I6 does so for attested mailboxes). Open decision 2.
- **Expected utility.** CaMeL solves 77 percent of AgentDojo tasks with provable security, against 84 percent undefended ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)). Expect a similar gap with `Trusted` requirements, narrowed by quarantined continuations (I22) and operator-bound trusted routes (I5).
- **What to report.** Utility, false-deny rate, and the endorsement rate, which measures human burden (section 14).

## 12. Surfaces and framework independence

- **Process workers.** These are any framework running as a Chio process (LangGraph, AI SDK, mini-SWE, coding-agent plugins). They get the full guarantee when the worker profile is `container` with pinned inputs, or `split_domain` (I7). The guarantee does not depend on the framework's language or interpreter.
- **Kernel sessions through MCP edges or the sidecar.** These start at `unknown`, because the client's model context includes inputs the kernel never saw.
  - Integrity-gated grants deny there, with `InsufficientIntegrity` and remedy class "run as a mediated process".
  - Grants without the constraint behave as today.
  - A deployment cannot declare an MCP client "trusted", because the kernel cannot verify complete mediation (open decision 3).
- **Hosted sessions** follow the kernel-session rule.

## 13. Receipts and evidence

25. **I25. Receipt metadata.** Every receipt for a grant with a requirement or floor carries `chio_runtime.integrity`:
    - `required`;
    - `satisfied_by`: `context`, `endorsement` or `bounded`;
    - the `context_generation`;
    - the opaque influence `commitment`;
    - the floor source, when a floor applied.

    Deny receipts carry the fault block (I19). Auditors can join any consequential effect to the influence commitment that admitted it.

## 14. Evaluation plan

- **Benchmarks.**
  - AgentDojo: 97 tasks and 629 security cases ([leaderboard](https://agentdojo.spylab.ai)).
  - AgentDyn: dynamic, open-ended tasks.
  - PIArena ([arXiv 2604.08499](https://arxiv.org/abs/2604.08499)).
- **Attackers.** Adaptive attackers in the method of Zhan et al. ([arXiv 2503.00061](https://arxiv.org/abs/2503.00061)): attacks optimized against the deployed system, not static injection strings.
- **Configurations.**
  - Undefended.
  - Integrity gating with `Trusted` requirements.
  - Gating plus quarantined continuations.
  - Gating plus endorsement.

  Each runs across at least three frameworks running as Chio processes.
- **Metrics.**
  - Attack success rate on consequential actions.
  - Utility, as task success.
  - False-deny rate.
  - Endorsements per task.
  - Mediation overhead.
- **Success criteria.**
  - Zero successful injections that cause a gated consequential call without an endorsement. The property holds by construction, and the evaluation confirms the implementation.
  - Utility within 10 points of undefended with quarantine templates.
  - The methodology, seeds and traces are published.
- **Honesty.** Static-benchmark "0 percent" claims are not reported.

## 15. Failure modes

| Failure | Behavior |
|---|---|
| No security context for a gated grant | Deny (I13) |
| Influence port or summary row unavailable | Deny |
| Summary row mismatch at startup | Not ready (I16) |
| Unbound route output | Joins `External` (I5) |
| Manifest digest changed under an operator binding | The binding is void; output joins `External` |
| Join commits before the intent commit | Intent commit fails `InsufficientIntegrity` (I15) |
| Endorsement `influence_basis` stale (context gained influence since) | The endorsement does not apply; deny |
| Portable core receives the constraint | `ConstraintError` deny (I11) |
| Typed return outside its type | Return refused; no fallback (I23) |

## 16. Protocol, schema and wire impact

- `spec/PROTOCOL.md` section 5: the `required_integrity` constraint (vocabulary, ordering, preservation rule I9, KG4 support condition).
- Section 6: `chio_runtime.integrity` receipt metadata, and the `InsufficientIntegrity` fault block.
- Section 8: deployment integrity bindings and floors.
- New schemas:
  - `chio.integrity-requirement.v1`;
  - `chio.influence-state.v1`;
  - `chio.integrity-deployment-binding.v1`;
  - `chio.confined-return-type.v1`.
- Changes to W: closed enums: `ExplanationFactKind::Integrity`, the `QuarantinedContinuation` template, and `InfluenceOriginV1`. These are additive.
- Process ABI: no new op. Influence travels in existing invoke and receive outcomes.

## 17. Rollout

1. **Output joins (I4-I8)** behind `integrity-tracking`, recording influence without gating. This also replaces the unconditional external marking.
2. **The constraint, the guard, and crossing check 4 (I9-I17)** behind `integrity-gating`. Grants opt in.
3. **The fault, endorsement and quarantined continuation (I18-I22)**, with typed returns (I23-I24).
4. **Evaluation publication**, then optional deployment floors (I12).

GT1 applies: no guarantee is claimed until the conformance scenarios run in hosted CI.

## 18. Tests and conformance evidence

- **Proptest.**
  - Lattice laws: join is commutative, associative and idempotent, and monotone (I2).
  - `satisfies` is antitone in state.
  - Attenuation never weakens a requirement (I9).
- **Loom.** A join racing an intent commit on the same context gives exactly one order. A post-join intent fails (I15).
- **Kani.** `satisfies` is total, and `unknown` always fails.
- **Unit.**
  - Unbound routes join `External`.
  - The operator binding is voided by a manifest change.
  - Attested mailbox inheritance.
  - Initial influence per worker profile.
  - Typed return capacity and projection rejection.
- **Conformance.**
  - An injected tool output followed by a consequential call is denied.
  - The quarantined continuation succeeds under `BoundedExternal`.
  - A same-principal endorsement replayed after new influence is refused.
  - MCP-edge gated grants deny.
  - A cross-process taint in one runtime denies, with no cause disclosed.
- **Adversarial suite.** Adaptive injection cases from section 14 are added to `chio-adversarial-suite`.

## 19. Residual risks and open decisions

Residual risks:
- Channels outside mediation (a `direct` worker reading the network) are the reason such contexts start at `unknown`. A misdeclared worker profile breaks the premise, so the attribution must be host-sourced (spec 7).
- Operator-bound `Trusted` routes are a trust decision. A wrong binding admits injection through that route.
- Bounded returns still carry information, up to `max_bits`. `Identifier` returns of 64 characters can encode short strings, so grants choose `n`.
- Session-wide keys over-taint (section 11).

Open decisions:
1. **The default floor.** Opt-in per grant (proposed), or a default floor for `destructive` and monetary effects once evaluation numbers exist?
2. **Lineage-scoped keys.** Narrow to lineage once every inter-process channel carries influence?
3. **MCP clients.** Allow an attested-client profile (a client attests complete mediation inside a TEE) to start trusted, or never?
4. **Provider origins.** `ModelProvider` as a separate class, or always `External`?
5. **P5 change.** I8 replaces the copied `External` with `ExternalBounded` on returns. The P5 owners must confirm this matches SEC-05 as intended, since history is retained in `commitment` but the class differs.

## Appendix A. CaMeL, FIDES and the FTL lesson

| | CaMeL | FIDES | Chio (this design) |
|---|---|---|---|
| Enforcement point | Custom Python interpreter | Planner | Kernel admission and the intent commit |
| Quarantine | Quarantined LLM without tools | Hidden variables; constrained queries | P5 confined reader in an OS cage with `FullyEnforced` evidence; typed returns |
| Label | Per-value capabilities | Confidentiality and integrity labels per message | P4 influence state per context, monotone, in the serving writer |
| Endorse | Policy functions | `reveal` and endorse | Exact endorsement (`IntegrityEndorsement`, `ScopedEndorsementV1`); never rewrites history |
| Framework scope | One interpreter | One planner | Any framework running as a mediated process |

**The FTL lesson.** FTL's `lx` enforces its policy in the same address space as the application it polices, so the policy is advisory (FTL `lx/src/thread.rs:58`, `lx/src/process.rs:81`). A framework-level injection defense has the same flaw: the agent and its injected content share the domain doing the enforcement. This design moves enforcement out of that domain:
- into the kernel's writer, for the check;
- into a cage, for the quarantine.

Here the analogy holds exactly.
